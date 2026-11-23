"""Regression tests for v1.3.1 community-prescribed improvements."""

from __future__ import annotations

import subprocess
from pathlib import Path

from athena.git_inspector import detect_working_tree_drift, extract_revision_range_data
from athena.graph_store import build_code_graph
from athena.release_notes import run_breaking_change_detection
from athena.test_selector import predict_affected_tests


def _init_git(repo: Path) -> None:
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=str(repo), check=True, capture_output=True)


def test_working_tree_stat_first_toctou_drift(tmp_path: Path) -> None:
    repo = tmp_path / "wt_repo"
    repo.mkdir()
    _init_git(repo)
    f = repo / "app.py"
    f.write_text("def greet():\n    return 'hi'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), check=True, capture_output=True)

    f.write_text("def greet(name: str = 'world'):\n    return name\n", encoding="utf-8")
    ext = extract_revision_range_data(repo, base_ref="HEAD", target_ref="WORKING_TREE")
    assert "app.py" in ext.working_tree_stats
    assert detect_working_tree_drift(ext) == []

    # Mutate file on disk after extraction -> stat-first drift must catch it
    f.write_text("def greet(name: str):\n    return name + '!'\n", encoding="utf-8")
    assert detect_working_tree_drift(ext) == ["app.py"]


def test_unit_shift_heuristic_on_timeout_ms_to_s(tmp_path: Path) -> None:
    repo = tmp_path / "unit_repo"
    repo.mkdir()
    _init_git(repo)
    (repo / "client.py").write_text(
        "def fetch(timeout: int) -> float:\n"
        "    return timeout / 1000.0\n",
        encoding="utf-8",
    )
    (repo / "caller.py").write_text(
        "from client import fetch\n"
        "REQUEST_TIMEOUT_MS = 5000\n"
        "fetch(REQUEST_TIMEOUT_MS)\n"
        "fetch(5000)\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "v1"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "tag", "v1.0"], cwd=str(repo), check=True, capture_output=True)

    (repo / "client.py").write_text(
        "def fetch(timeout: int) -> float:\n"
        "    return float(timeout)\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "v2"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "tag", "v2.0"], cwd=str(repo), check=True, capture_output=True)

    report = run_breaking_change_detection(str(repo), base_ref="v1.0", target_ref="v2.0", use_llm=False)
    assert report.status == "ok"
    assert any("unit-shift" in f.model_interpretation.lower() for f in report.potential_breaking_changes)


def test_ts_barrel_reexport_chain(tmp_path: Path) -> None:
    repo = tmp_path / "barrel_repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "inner.ts").write_text("export function computeTax(x: number): number { return x * 0.1; }\n", encoding="utf-8")
    (repo / "pkg" / "index.ts").write_text("export { computeTax } from './inner';\n", encoding="utf-8")
    (repo / "app.ts").write_text("import { computeTax } from './pkg';\nexport function run() { return computeTax(10); }\n", encoding="utf-8")

    cg = build_code_graph(repo, persist=False, use_cache=False)
    edge_pairs = {(e.source, e.target, e.relation) for e in cg.edges}
    assert ("mod:app.ts", "mod:pkg/index.ts", "imports") in edge_pairs
    assert ("mod:pkg/index.ts", "mod:pkg/inner.ts", "imports") in edge_pairs


def test_php_laravel_facade_and_container_unknowns(tmp_path: Path) -> None:
    repo = tmp_path / "laravel_repo"
    repo.mkdir()
    (repo / "Provider.php").write_text(
        "<?php\n"
        "class AppServiceProvider {\n"
        "    public function register() {\n"
        "        $this->app->singleton('cache', function () { return null; });\n"
        "    }\n"
        "    public static function __callStatic($method, $args) { return null; }\n"
        "}\n",
        encoding="utf-8",
    )
    cg = build_code_graph(repo, persist=False, use_cache=False)
    assert cg.completeness == "partial"
    assert len(cg.unknowns) >= 2
    assert all(u.kind == "dynamic_dispatch" for u in cg.unknowns)


def test_predict_affected_tests_and_cuda_tex_extraction(tmp_path: Path) -> None:
    repo = tmp_path / "e2e_cuda_repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir(parents=True)
    _init_git(repo)

    (repo / "src" / "checkout.ts").write_text("export function submitOrder() { return true; }\n", encoding="utf-8")
    (repo / "tests" / "checkout.spec.ts").write_text(
        "import { submitOrder } from '../src/checkout';\ntest('e2e', () => { submitOrder(); });\n",
        encoding="utf-8",
    )
    (repo / "tests" / "unrelated.spec.ts").write_text("test('other', () => {});\n", encoding="utf-8")
    (repo / "src" / "kernel.cu").write_text(
        "__global__ void saxpy_kernel(int n, float a, float *x, float *y) {}\n",
        encoding="utf-8",
    )
    (repo / "paper.tex").write_text("\\section{Architecture}\n\\newcommand{\\athena}{Athena}\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "v1"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "tag", "v1.0"], cwd=str(repo), check=True, capture_output=True)

    (repo / "src" / "checkout.ts").write_text("export function submitOrder(id: string) { return Boolean(id); }\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "v2"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "tag", "v2.0"], cwd=str(repo), check=True, capture_output=True)

    res = predict_affected_tests(repo, base_ref="v1.0", target_ref="v2.0")
    assert res["selected_count"] == 1
    assert res["selected_tests"][0]["test_file"] == "tests/checkout.spec.ts"
    assert res["selected_tests"][0]["is_e2e"] is True

    cg = build_code_graph(repo, persist=False, use_cache=False)
    labels = {n.label for n in cg.nodes}
    assert "saxpy_kernel" in labels
    assert "Architecture" in labels
    assert "athena" in labels
