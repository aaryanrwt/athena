"""Representative multi-language Athena workload for profiling and Rust acceleration via `fast-anything`."""

from __future__ import annotations

from pathlib import Path

from athena._fast_kernels import parse_unified_diff_raw
from athena.ast_analyzer import _parse_multilang_symbols_uncached
from athena.graph_query import query_code_graph
from athena.graph_store import build_code_graph
from athena.release_notes import run_breaking_change_detection
from athena.security import redact_secrets

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / ".fast" / "bench_fixture"


def _ensure_fixture(fixture_dir: Path) -> Path:
    marker = fixture_dir / ".ready"
    diff_path = fixture_dir / "sample_large.diff"
    if marker.is_file() and diff_path.is_file():
        return diff_path

    fixture_dir.mkdir(parents=True, exist_ok=True)
    # 180 multi-language modules (~14 symbols + imports each => ~2,700 nodes, ~6,000+ edges)
    for i in range(25):
        ts_dir = fixture_dir / f"pkg_ts_{i:02d}"
        ts_dir.mkdir(exist_ok=True)
        (ts_dir / "inner.ts").write_text(
            "\n".join(
                f"export function tsServiceFn_{i}_{k}(timeoutMs: number, userId: string): string {{ return userId; }}"
                for k in range(10)
            )
            + f"\nexport interface ServiceConfig_{i} {{ timeoutMs: number; }}\n"
            + f"export class ServiceHandler_{i} {{}}\n",
            encoding="utf-8",
        )
        (ts_dir / "index.ts").write_text(
            "export { "
            + ", ".join(f"tsServiceFn_{i}_{k}" for k in range(10))
            + " } from './inner';\n",
            encoding="utf-8",
        )
        prev1 = f"../pkg_ts_{(i - 1) % 25:02d}"
        prev2 = f"../pkg_ts_{(i - 2) % 25:02d}"
        prev3 = f"../pkg_ts_{(i - 3) % 25:02d}"
        (ts_dir / "consumer.ts").write_text(
            f"import {{ tsServiceFn_{(i - 1) % 25:02d}_0 }} from '{prev1}';\n"
            f"import {{ tsServiceFn_{(i - 2) % 25:02d}_1 }} from '{prev2}';\n"
            f"import {{ tsServiceFn_{(i - 3) % 25:02d}_2 }} from '{prev3}';\n"
            + "\n".join(
                f"export function runConsumer_{i}_{k}(x: number): number {{ return x + {k}; }}"
                for k in range(12)
            )
            + "\n",
            encoding="utf-8",
        )

    for i in range(20):
        (fixture_dir / f"worker_{i:02d}.go").write_text(
            "package worker\n"
            f'import "worker_{(i - 1) % 20:02d}"\n'
            f'import "worker_{(i - 2) % 20:02d}"\n'
            f'import "worker_{(i - 3) % 20:02d}"\n'
            + "\n".join(
                f"func (w *Worker{i}) HandleJob_{i}_{k}(ctx Context, timeout int) error {{ return nil }}"
                for k in range(20)
            )
            + f"\ntype Worker{i} struct {{ id int }}\n",
            encoding="utf-8",
        )
        (fixture_dir / f"engine_{i:02d}.rs").write_text(
            f"use crate::engine_{(i - 1) % 20:02d};\n"
            f"use crate::engine_{(i - 2) % 20:02d};\n"
            + "\n".join(
                f"pub fn process_batch_{i}_{k}(items: &[u8], limit: usize) -> usize {{ limit }}"
                for k in range(20)
            )
            + f"\npub struct EngineState_{i} {{ count: usize }}\n",
            encoding="utf-8",
        )
        (fixture_dir / f"facade_{i:02d}.php").write_text(
            "<?php\n"
            f"class BillingFacade_{i} {{\n"
            f"    public static function __callStatic($m, $a) {{ return null; }}\n"
            + "\n".join(
                f"    public function chargeInvoice_{i}_{k}($amount, $currency) {{ return $amount; }}"
                for k in range(10)
            )
            + "\n}\n",
            encoding="utf-8",
        )
        (fixture_dir / f"kernel_{i:02d}.cu").write_text(
            "\n".join(
                f"__global__ void cuda_saxpy_kernel_{i}_{k}(int n, float a, float *x, float *y) {{}}"
                for k in range(8)
            )
            + f"\nstruct KernelMetrics_{i} {{ float elapsed; }};\n",
            encoding="utf-8",
        )
        (fixture_dir / f"paper_{i:02d}.tex").write_text(
            "\n".join(
                f"\\section{{Section Title {i} Part {k}}}\n\\subsection{{Sub {k}}}\n"
                for k in range(8)
            )
            + f"\\newcommand{{\\macroOp{i}}}[1]{{#1}}\n",
            encoding="utf-8",
        )

    # Synthetic tokens assembled dynamically for redaction stress testing
    fake_gh = "ghp_" + "A1B2C3D4E5" * 4
    fake_oai = "sk-proj-" + "Xy9Zw8Vu7T" * 3
    fake_aws = "AKIA" + "0123456789ABCDEF"
    diff_chunks: list[str] = []
    for idx in range(45):
        lines = [
            f"diff --git a/src/mod_{idx:02d}.py b/src/mod_{idx:02d}.py",
            "index 1111111..2222222 100644",
            f"--- a/src/mod_{idx:02d}.py",
            f"+++ b/src/mod_{idx:02d}.py",
            f"@@ -10,12 +10,14 @@ def process_batch_{idx}(timeout: int):",
            "-    api_key = 'placeholder_old_value'",
            f"+    token = '{fake_gh}'",
            f"+    openai_key = '{fake_oai}'",
            f"+    aws_id = '{fake_aws}'",
            "+    url = 'https://service_user:superSecretPass123@api.internal/v1'",
            "+    bearer = 'Authorization: Bearer " + fake_gh + "'",
            f"+    mixed = \"rT9#kL2$mN8pQ4xW7zY3vB6nM1cK5jH0\"  # high entropy",
        ]
        for ln in range(25):
            lines.append(f"+    val_{ln} = timeout * {ln + 1}  # clean line {idx}_{ln}")
        diff_chunks.append("\n".join(lines))

    diff_path.write_text("\n".join(diff_chunks) + "\n", encoding="utf-8")
    marker.write_text("ok\n", encoding="utf-8")
    return diff_path


def run_workload() -> None:
    diff_path = _ensure_fixture(FIXTURE_DIR)
    diff_text = diff_path.read_text(encoding="utf-8")
    ts_sample = (FIXTURE_DIR / "pkg_ts_00" / "inner.ts").read_text(encoding="utf-8")
    go_sample = (FIXTURE_DIR / "worker_00.go").read_text(encoding="utf-8")
    rs_sample = (FIXTURE_DIR / "engine_00.rs").read_text(encoding="utf-8")
    php_sample = (FIXTURE_DIR / "facade_00.php").read_text(encoding="utf-8")

    # 1. Code graph extraction & deterministic community clustering on multi-lang repo
    fg = build_code_graph(FIXTURE_DIR, persist=False, use_cache=False)
    for _ in range(2):
        fg = build_code_graph(FIXTURE_DIR, persist=False, use_cache=False)

    # 2. Trigram + IDF graph query workload across 30 queries
    queries = (
        "tsServiceFn_12_3 timeoutMs",
        "cuda_saxpy_kernel_05_2 metrics",
        "BillingFacade_10 chargeInvoice",
        "Worker HandleJob Context",
        "process_batch EngineState storage",
        "runConsumer tsServiceFn",
    ) * 5
    total_seeds = 0
    for q_text in queries:
        q_res = query_code_graph(fg, q_text, depth=2, token_budget=2000)
        total_seeds += int(q_res["seed_count"])

    # 3. Unified diff parsing + secret redaction on large diff
    parsed_total = 0
    redacted_chars = 0
    for _ in range(20):
        parsed = parse_unified_diff_raw(diff_text)
        parsed_total += len(parsed)
        redacted_chars += len(redact_secrets(diff_text))

    # 4. Multi-language AST/signature extraction
    sym_total = 0
    for _ in range(15):
        sym_total += len(_parse_multilang_symbols_uncached(ts_sample, "inner.ts"))
        sym_total += len(_parse_multilang_symbols_uncached(go_sample, "worker.go"))
        sym_total += len(_parse_multilang_symbols_uncached(rs_sample, "engine.rs"))
        sym_total += len(_parse_multilang_symbols_uncached(php_sample, "facade.php"))

    # 5. Real repository graph + git breaking-change detection pass
    self_graph = build_code_graph(REPO_ROOT, persist=False, use_cache=False)
    report = run_breaking_change_detection(
        str(REPO_ROOT),
        base_ref="v1.0.0",
        target_ref="v1.3.1",
        use_llm=False,
    )

    print(
        f"fixture_nodes={len(fg.nodes)} fixture_edges={len(fg.edges)} "
        f"communities={len(fg.community_labels)} seeds={total_seeds} "
        f"diff_files={parsed_total} redacted_len={redacted_chars} syms={sym_total} "
        f"self_nodes={len(self_graph.nodes)} findings={len(report.potential_breaking_changes)}"
    )


if __name__ == "__main__":
    run_workload()
