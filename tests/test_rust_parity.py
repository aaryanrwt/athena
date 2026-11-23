"""Cross-verification parity tests proving Athena Rust accelerations produce
zero quality or behavioral degradation vs pure-Python fallback (`FAST_ANYTHING_DISABLE=1`)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from athena._fast_kernels import (
    compute_community_assignments,
    extract_structural_symbols_raw,
    parse_unified_diff_raw,
    score_graph_trigrams,
)
from athena.graph_query import query_code_graph
from athena.graph_store import build_code_graph
from athena.release_notes import run_breaking_change_detection
from athena.security import redact_secrets

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_python_fallback_snippet(code: str) -> dict:
    env = os.environ.copy()
    env["FAST_ANYTHING_DISABLE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return json.loads(proc.stdout)


def test_kernel_edge_cases_and_parity_against_python_fallback() -> None:
    payload = {
        "nodes": ["n1", "n2", "n3_test", "b_α", "a_β"],
        "is_test": [False, False, True, False, False],
        "labels": ["Alpha", "Beta", "TestGamma", "NodeAlpha", "NodeBeta"],
        "paths": ["src/alpha.ts", "src/beta.ts", "tests/test_g.py", "src/unicøde.cu", "src/doc.tex"],
        "edges": [
            ("n1", "n2", "calls", 1.0, "observed"),
            ("n2", "n3_test", "imports", 1.0, "inferred"),
            ("b_α", "a_β", "calls", 1.0, "observed"),
            ("n1", "n1", "calls", 1.0, "observed"),
        ],
        "samples": [
            ("typescript", "import { x } from './inner';\r\n// export function fake() {}\r\nexport function realFn(a: number): number { return a; }\r\nexport const arrowFn = async (b: string) => b;\r\n"),
            ("php", "<?php\nclass Facade { public static function __callStatic($m, $a) {} public function run($x) {} }\n$app->singleton('x', fn() => 1);\n"),
            ("cuda", "__global__ void saxpy_k(int n, float a, float *x, float *y) {}\nstruct CudaMetrics { int n; };\n"),
            ("tex", "\\section{Introduction}\n\\subsection*{Details}\n\\newcommand{\\myMacro}[1]{#1}\n"),
            ("javascript", "export { foo } from './bar';\n" + ("x" * 513) + "\nfunction shortAfterMinified(a) {}\n"),
        ],
        "secrets": [
            "",
            "clean string without credentials",
            "https://alice:topsecret@example.com/v1?x=" + ("ghp_" + "A1B2C3D4E5" * 3),
            "Authorization: Bearer sk-ant-" + ("z" * 24) + " aws=" + ("AKIA" + "0123456789ABCDEF"),
            'api_key = "super_secret_12345" high="aB3$cD7!eF9@gH2#iJ4%kL6^mN8&pQ1"',
            "-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----",
        ],
    }

    py_out = _run_python_fallback_snippet(
        "import json\n"
        "from athena._fast_kernels import compute_community_assignments, extract_structural_symbols_raw, parse_unified_diff_raw, score_graph_trigrams\n"
        "from athena.security import redact_secrets\n"
        f"p = {json.dumps(payload)!r}\n"
        "d = json.loads(p)\n"
        "edges = [tuple(e) for e in d['edges']]\n"
        "comm, clab = compute_community_assignments(d['nodes'], d['is_test'], d['labels'], edges)\n"
        "sc, seeds = score_graph_trigrams(d['nodes'], d['labels'], d['paths'], d['is_test'], ['alpha', 'unicøde'], False)\n"
        "exts = [extract_structural_symbols_raw(lang, src) for lang, src in d['samples']]\n"
        "reds = [redact_secrets(s) for s in d['secrets']]\n"
        "print(json.dumps({'comm': comm, 'clab': clab, 'sc': sc, 'seeds': seeds, 'exts': exts, 'reds': reds}))\n"
    )

    comm_now, clab_now = compute_community_assignments(
        payload["nodes"],
        payload["is_test"],
        payload["labels"],
        payload["edges"],
    )
    assert comm_now == py_out["comm"]
    assert clab_now == py_out["clab"]

    sc_now, seeds_now = score_graph_trigrams(
        payload["nodes"],
        payload["labels"],
        payload["paths"],
        payload["is_test"],
        ["alpha", "unicøde"],
        False,
    )
    assert seeds_now == py_out["seeds"]
    assert set(sc_now) == set(py_out["sc"])
    for k, v in sc_now.items():
        assert v == pytest.approx(py_out["sc"][k], rel=1e-9, abs=1e-12)

    exts_now = [list(map(list, extract_structural_symbols_raw(lang, src))) for lang, src in payload["samples"]]
    # Convert tuple symbols (sym, line) inside first item for JSON-equivalent comparison
    exts_norm = [[[[s[0], s[1]] for s in item[0]], item[1], item[2]] for item in exts_now]
    assert exts_norm == py_out["exts"]

    reds_now = [redact_secrets(s) for s in payload["secrets"]]
    assert reds_now == py_out["reds"]

    # Sanity check unified diff parser directly
    parsed = parse_unified_diff_raw("diff --git a/a.py b/a.py\n@@ -1,1 +1,2 @@\n+x = 1\n")
    assert parsed == [("a.py", [("@@ -1,1 +1,2 @@", 1, 1, 1, 2, "+x = 1")], 1, 0, False)]


def test_end_to_end_repo_analysis_parity_against_python_fallback() -> None:
    py_e2e = _run_python_fallback_snippet(
        "import json\n"
        "from pathlib import Path\n"
        "from athena.graph_store import build_code_graph\n"
        "from athena.graph_query import query_code_graph\n"
        "from athena.release_notes import run_breaking_change_detection\n"
        "g = build_code_graph(Path('.'), persist=False, use_cache=False)\n"
        "q = query_code_graph(g, 'breaking change ast graph community', depth=2, token_budget=2000)\n"
        "r = run_breaking_change_detection('.', base_ref='v1.0.0', target_ref='v1.3.1', use_llm=False)\n"
        "print(json.dumps({\n"
        "  'ev': g.graph_evidence_id,\n"
        "  'comp': g.completeness,\n"
        "  'files': g.total_files_scanned,\n"
        "  'nodes': len(g.nodes),\n"
        "  'edges': len(g.edges),\n"
        "  'clab': g.community_labels,\n"
        "  'unks': len(g.unknowns),\n"
        "  'q_seeds': q['seed_count'],\n"
        "  'q_nodes': [n['id'] for n in q['subgraph_nodes']],\n"
        "  'q_edges': sorted([[e['source'], e['target'], e['relation']] for e in q['subgraph_edges']]),\n"
        "  'q_tok': q['estimated_tokens'],\n"
        "  'brk': sorted([[f.file_path, f.affected_symbol or '', f.change_kind, f.severity, len(f.affected_callers)] for f in r.potential_breaking_changes]),\n"
        "}))\n"
    )

    g = build_code_graph(_REPO_ROOT, persist=False, use_cache=False)
    q = query_code_graph(g, "breaking change ast graph community", depth=2, token_budget=2000)
    r = run_breaking_change_detection(str(_REPO_ROOT), base_ref="v1.0.0", target_ref="v1.3.1", use_llm=False)

    assert g.graph_evidence_id == py_e2e["ev"]
    assert g.completeness == py_e2e["comp"]
    assert g.total_files_scanned == py_e2e["files"]
    assert len(g.nodes) == py_e2e["nodes"]
    assert len(g.edges) == py_e2e["edges"]
    assert g.community_labels == py_e2e["clab"]
    assert len(g.unknowns) == py_e2e["unks"]

    assert q["seed_count"] == py_e2e["q_seeds"]
    assert [n["id"] for n in q["subgraph_nodes"]] == py_e2e["q_nodes"]
    assert sorted([[e["source"], e["target"], e["relation"]] for e in q["subgraph_edges"]]) == py_e2e["q_edges"]
    assert q["estimated_tokens"] == py_e2e["q_tok"]

    brk_now = sorted(
        [[f.file_path, f.affected_symbol or "", f.change_kind, f.severity, len(f.affected_callers)] for f in r.potential_breaking_changes]
    )
    assert brk_now == py_e2e["brk"]
