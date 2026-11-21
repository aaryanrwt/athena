"""Real Benchmark & Mutation Verification Harness for Athena v1.3.0.

Measures real wall-clock latency, incremental cache speedup, token reduction
(naive corpus vs. repo_map + query_code_graph), MCP catalog byte reduction, and
mutation-detection accuracy on real repositories (zero synthetic/faked numbers).
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from athena.debt_tracker import scan_shortcut_debt
from athena.graph_query import query_code_graph
from athena.graph_store import _collect_tracked_source_files, build_code_graph
from athena.mcp_server import _TOOL_CATALOG_METADATA
from athena.release_notes import run_breaking_change_detection
from athena.repo_map import build_repo_map


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def run_athena_v13_benchmark(repo_path: Path) -> dict[str, Any]:
    """Run deterministic performance, token-reduction, and mutation checks on a real repo."""
    # 1. Cold vs incremental graph build
    t0 = time.perf_counter()
    cg_cold = build_code_graph(repo_path, persist=True, use_cache=False)
    cold_ms = (time.perf_counter() - t0) * 1000.0

    t1 = time.perf_counter()
    cg_warm = build_code_graph(repo_path, persist=True, use_cache=True)
    warm_ms = (time.perf_counter() - t1) * 1000.0

    # 2. Naive corpus tokens vs repo_map + graph query tokens
    files = _collect_tracked_source_files(repo_path)
    total_corpus_bytes = sum(f.stat().st_size for f in files if f.is_file())
    naive_tokens = max(1, total_corpus_bytes // 4)

    rmap = build_repo_map(repo_path, max_chars=2000, graph=cg_warm)
    qres = query_code_graph(cg_warm, "breaking change ast analyzer evidence", depth=2, token_budget=2000)
    athena_tokens = _estimate_tokens(rmap["map_text"]) + int(qres.get("estimated_tokens", 0))
    reduction_x = round(naive_tokens / max(1, athena_tokens), 2)

    # 3. Hot vs full catalog metadata ratio
    hot_tools = [t for t in _TOOL_CATALOG_METADATA if t["tier"] == "hot"]
    catalog_reduction_pct = round((1.0 - (len(hot_tools) / len(_TOOL_CATALOG_METADATA))) * 100.0, 1)

    # 4. Real mutation verification (inject 3 real code defects in an isolated temp git repo)
    mutation_results = _run_mutation_checks()

    return {
        "repo": str(repo_path),
        "files_scanned": cg_cold.total_files_scanned,
        "nodes": len(cg_cold.nodes),
        "edges": len(cg_cold.edges),
        "communities": len(cg_cold.community_labels),
        "unknowns": len(cg_cold.unknowns),
        "cold_build_ms": round(cold_ms, 2),
        "warm_cache_build_ms": round(warm_ms, 2),
        "naive_corpus_tokens": naive_tokens,
        "athena_map_plus_query_tokens": athena_tokens,
        "token_reduction_factor": f"{reduction_x}x",
        "hot_catalog_tools": len(hot_tools),
        "total_catalog_tools": len(_TOOL_CATALOG_METADATA),
        "hot_catalog_reduction_pct": catalog_reduction_pct,
        "mutations": mutation_results,
    }


def _run_mutation_checks() -> dict[str, Any]:
    """Inject real breaking/debt/unknown mutations in a temp Git repo and verify detection."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "mut_repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Mut"], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "m@e.com"], cwd=str(repo), check=True, capture_output=True)

        (repo / "api.py").write_text(
            "def charge_card(amount: int, currency: str = 'USD') -> bool:\n"
            "    return amount > 0\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "v1"], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(["git", "tag", "v1.0.0"], cwd=str(repo), check=True, capture_output=True)

        # Mutate: remove default, add unguarded dynamic dispatch, add shortcut without trigger
        (repo / "api.py").write_text(
            "def charge_card(amount: int, currency: str) -> bool:\n"
            "    # shortcut: hardcoded fee bypass\n"
            "    handler = getattr(__builtins__, 'abs')\n"
            "    return handler(amount) > 0\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "v2"], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(["git", "tag", "v2.0.0"], cwd=str(repo), check=True, capture_output=True)

        brk = run_breaking_change_detection(str(repo), base_ref="v1.0.0", target_ref="v2.0.0", use_llm=False)
        debt = scan_shortcut_debt(repo)
        cg = build_code_graph(repo, persist=False, use_cache=False)

        caught_breaking = len(brk.potential_breaking_changes) >= 1
        caught_missing_trigger = debt.missing_trigger_count == 1
        caught_unknown = any(u.kind == "dynamic_dispatch" for u in cg.unknowns)
        passed = sum([caught_breaking, caught_missing_trigger, caught_unknown])

        return {
            "caught_breaking_change": caught_breaking,
            "caught_missing_shortcut_trigger": caught_missing_trigger,
            "caught_dynamic_dispatch_unknown": caught_unknown,
            "score": f"{passed}/3",
        }


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[2]
    report = run_athena_v13_benchmark(root)
    print(json.dumps(report, indent=2))
