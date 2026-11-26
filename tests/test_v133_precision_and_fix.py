"""Comprehensive precision, Tree-sitter/fallback parity, remediation, and ledger tests for Athena v1.3.3."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from athena.ast_analyzer import analyze_python_module_diff, run_structural_code_analysis
from athena.cli import main as cli_main
from athena.evidence_store import never_worse_payload, truncate_head_tail
from athena.git_inspector import decode_bytes_safely, extract_revision_range_data
from athena.mcp_server import _TOOL_CATALOG_METADATA, create_mcp_server, mcp_app
from athena.release_notes import run_breaking_change_detection
from athena.remediation import generate_fix_plan
from athena.token_ledger import read_gain_report, record_token_saving, reset_gain_ledger


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init")
    _git(repo, "config", "user.name", "Tester")
    _git(repo, "config", "user.email", "tester@example.com")


def _extract_resource_text(res: Any) -> str:
    if isinstance(res, str):
        return res
    contents = getattr(res, "contents", res)
    if isinstance(contents, (list, tuple)) and contents:
        first = contents[0]
        return str(getattr(first, "content", getattr(first, "text", first)))
    return str(getattr(contents, "content", getattr(contents, "text", contents)))


@pytest.mark.parametrize("disable_ts", ["0", "1"])
def test_csharp_modifier_reorder_produces_zero_breaking_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disable_ts: str,
) -> None:
    monkeypatch.setenv("ATHENA_TREESITTER_DISABLE", disable_ts)
    repo = tmp_path / f"cs_mod_{disable_ts}"
    _init_repo(repo)
    cs_file = repo / "AggregatorAgent.cs"
    cs_file.write_text(
        "namespace Demo.Agents {\n"
        "  public class AggregatorAgent {\n"
        "    protected internal async override Task<AgentChannel> RestoreChannelAsync(\n"
        "        string channelState, CancellationToken cancellationToken) {\n"
        "      return await BaseRestoreAsync(channelState, cancellationToken);\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")
    _git(repo, "tag", "v1.0")

    cs_file.write_text(
        "namespace Demo.Agents {\n"
        "  public class AggregatorAgent {\n"
        "    protected internal override async Task<AgentChannel> RestoreChannelAsync(\n"
        "        string channelState, CancellationToken cancellationToken) {\n"
        "      return await BaseRestoreAsync(channelState, cancellationToken);\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "style: reorder C# modifiers")

    report = run_breaking_change_detection(str(repo), base_ref="v1.0", target_ref="HEAD", use_llm=False)
    assert report.status == "ok"
    assert report.total_potential_breaking_changes == 0


def test_go_unexported_and_receiver_scoped_callers_without_declarations(tmp_path: Path) -> None:
    repo = tmp_path / "go_precision"
    _init_repo(repo)
    gh = repo / "github"
    gh.mkdir()

    (gh / "dependabot_secrets.go").write_text(
        "package github\n"
        "func (s *DependabotService) CreateOrUpdateRepoSecret(ctx context.Context, owner, repo string, eSecret *EncryptedSecret) (*Response, error) {\n"
        "    return nil, nil\n"
        "}\n"
        "func (s *DependabotService) getPublicKey(ctx context.Context, url string) (*PublicKey, error) {\n"
        "    return nil, nil\n"
        "}\n",
        encoding="utf-8",
    )
    (gh / "actions_secrets.go").write_text(
        "package github\n"
        "func (s *ActionsService) CreateOrUpdateRepoSecret(ctx context.Context, owner, repo string, eSecret *EncryptedSecret) (*Response, error) {\n"
        "    return nil, nil\n"
        "}\n"
        "func (s *ActionsService) getPublicKey(ctx context.Context, url string) (*PublicKey, error) {\n"
        "    return s.getPublicKey(ctx, url)\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "app.go").write_text(
        "package main\n"
        "import \"example.com/github\"\n"
        "func main(client *github.Client) {\n"
        "    client.Codespaces.CreateOrUpdateRepoSecret(nil, \"o\", \"r\", nil)\n"
        "    client.Dependabot.CreateOrUpdateRepoSecret(nil, \"o\", \"r\", nil)\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init go")
    _git(repo, "tag", "v1.0")

    (gh / "dependabot_secrets.go").write_text(
        "package github\n"
        "func (s *DependabotService) CreateOrUpdateRepoSecret(ctx context.Context, owner, repo, name string, body SecretRequest) (*Response, error) {\n"
        "    return nil, nil\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat!: update DependabotService secret API and remove unexported getPublicKey")

    report = run_breaking_change_detection(str(repo), base_ref="v1.0", target_ref="HEAD", use_llm=False)
    assert report.status == "ok"
    syms = {f.affected_symbol: f for f in report.potential_breaking_changes}
    assert "DependabotService.CreateOrUpdateRepoSecret" in syms
    assert "DependabotService.getPublicKey" not in syms

    dep = syms["DependabotService.CreateOrUpdateRepoSecret"]
    assert dep.api_surface == "public_external"
    snippets = [c.call_snippet for c in dep.affected_callers]
    assert any("client.Dependabot.CreateOrUpdateRepoSecret" in s for s in snippets)
    assert not any("client.Codespaces.CreateOrUpdateRepoSecret" in s for s in snippets)
    assert not any(s.lstrip().startswith("func (") for s in snippets)


def test_cross_language_generic_name_and_nested_thirdparty_isolation(tmp_path: Path) -> None:
    repo = tmp_path / "isolation_repo"
    _init_repo(repo)
    (repo / "mlx" / "backend").mkdir(parents=True)
    (repo / "mlx" / "3rdparty").mkdir(parents=True)
    (repo / "bench").mkdir(parents=True)

    (repo / "mlx" / "backend" / "cuda.cpp").write_text(
        "bool is_available() { return true; }\n"
        "void release_mem_custom(void* buf) {}\n",
        encoding="utf-8",
    )
    (repo / "mlx" / "3rdparty" / "pocketfft.h").write_text(
        "void cleanup() { is_available(); release_mem_custom(0); }\n",
        encoding="utf-8",
    )
    (repo / "bench" / "bench_torch.py").write_text(
        "import torch\n"
        "def bench(data_dict):\n"
        "    keys = list(data_dict.keys())\n"
        "    if torch.cuda.is_available():\n"
        "        return len(keys)\n"
        "    return 0\n",
        encoding="utf-8",
    )
    (repo / "cli_mod.py").write_text(
        "def list(ctx):\n    return ctx\n"
        "def main():\n    return 0\n",
        encoding="utf-8",
    )
    (repo / "unrelated_script.py").write_text(
        "import sys\n"
        "def main():\n    return 1\n"
        "def run_check():\n    return sys.exit(main())\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")
    _git(repo, "tag", "v1.0")

    (repo / "mlx" / "backend" / "cuda.cpp").write_text("", encoding="utf-8")
    (repo / "cli_mod.py").write_text("", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "remove C++ symbols and Python CLI helpers")

    report = run_breaking_change_detection(str(repo), base_ref="v1.0", target_ref="HEAD", use_llm=False)
    assert report.status == "ok"
    by_sym = {f.affected_symbol: f for f in report.potential_breaking_changes}

    if "is_available" in by_sym:
        caller_files = [c.caller_file for c in by_sym["is_available"].affected_callers]
        assert "bench/bench_torch.py" not in caller_files
        assert "mlx/3rdparty/pocketfft.h" not in caller_files
    if "list" in by_sym:
        caller_files = [c.caller_file for c in by_sym["list"].affected_callers]
        assert "bench/bench_torch.py" not in caller_files
    if "main" in by_sym:
        caller_files = [c.caller_file for c in by_sym["main"].affected_callers]
        assert "unrelated_script.py" not in caller_files


def test_python_and_positional_param_precision_rules(tmp_path: Path) -> None:
    # 1. Python keyword-only widening, Optional[int] -> int return narrowing, & single variadic absorption
    old_py = (
        "from typing import Optional\n"
        "def calc(x: int, *, y: int = 1) -> Optional[int]:\n"
        "    return x + y\n"
        "def drop_kw(*, flag: bool = False) -> int:\n"
        "    return 1 if flag else 0\n"
    )
    new_py = (
        "def calc(x: int, y: int = 1) -> int:\n"
        "    return x + y\n"
        "def drop_kw(**kwargs: object) -> int:\n"
        "    return 0\n"
    )
    res = analyze_python_module_diff(old_py, new_py, file_path="math_api.py")
    assert all(not sc.is_breaking_candidate for sc in res.symbol_changes)

    # 2. Positional parameter-name-only rename in Go / C++ / Rust / Java
    repo = tmp_path / "pos_rename"
    _init_repo(repo)
    (repo / "lib.go").write_text("package p\nfunc Sum(a int, b int) int { return a + b }\n", encoding="utf-8")
    (repo / "lib.rs").write_text("pub fn mul(lhs: i32, rhs: i32) -> i32 { lhs * rhs }\n", encoding="utf-8")
    (repo / "Service.java").write_text(
        "public class Service { public int runOp(String cmd, int secs) { return secs; } }\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1")
    _git(repo, "tag", "v1.0")

    (repo / "lib.go").write_text("package p\nfunc Sum(left int, right int) int { return left + right }\n", encoding="utf-8")
    (repo / "lib.rs").write_text("pub fn mul(x: i32, y: i32) -> i32 { x * y }\n", encoding="utf-8")
    (repo / "Service.java").write_text(
        "public class Service { public int runOp(String inputCmd, int timeoutSec) { return timeoutSec; } }\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "rename params only")

    rep = run_breaking_change_detection(str(repo), base_ref="v1.0", target_ref="HEAD", use_llm=False)
    assert rep.total_potential_breaking_changes == 0


def test_non_utf8_and_crlf_only_diff_handling(tmp_path: Path) -> None:
    latin_bytes = "# Author: Ren\xe9\ndef greet(name: str) -> str:\n    return name\n".encode("cp1252")
    decoded = decode_bytes_safely(latin_bytes)
    assert "Ren\xe9" in decoded and "def greet" in decoded

    repo = tmp_path / "crlf_repo"
    _init_repo(repo)
    _git(repo, "config", "core.autocrlf", "false")
    mod = repo / "app.py"
    mod.write_bytes(b"def ping(host: str) -> bool:\n    return True\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init lf")
    _git(repo, "tag", "v1.0")

    mod.write_bytes(b"def ping(host: str) -> bool:\r\n    return True\r\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "chore: convert to CRLF")

    ext = extract_revision_range_data(repo, base_ref="v1.0", target_ref="HEAD")
    res = run_structural_code_analysis(ext)
    assert len(res.deterministic_breaking_findings) == 0


def test_remediation_fix_plan_dry_run_apply_and_conflict_guard(tmp_path: Path) -> None:
    repo = tmp_path / "fix_repo"
    _init_repo(repo)
    (repo / "api.py").write_text(
        "def connect(host: str, retries: int = 3) -> str:\n"
        '    """Connect.\n\n    :param retries: retry limit\n    """\n'
        "    return f'{host}:{retries}'\n",
        encoding="utf-8",
    )
    (repo / "worker.py").write_text(
        "from api import connect\n\n"
        "def sync_job() -> str:\n"
        "    return connect('db.local', retries=5)\n",
        encoding="utf-8",
    )
    (repo / "api_none.py").write_text("def tune(timeout: int = 30) -> int:\n    return timeout + 1\n", encoding="utf-8")
    (repo / "recur.py").write_text("class Node:\n    def walk(self, n: int) -> int:\n        return n\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1")
    _git(repo, "tag", "v1.0")

    # Introduce unguarded default=None + rename kwarg `retries` -> `max_retries` while docstring still says `:param retries:`
    (repo / "api.py").write_text(
        "def connect(host: str, max_retries: int | None = 3) -> str:\n"
        '    """Connect.\n\n    :param retries: retry limit\n    """\n'
        "    return f'{host}:{max_retries}'\n",
        encoding="utf-8",
    )
    (repo / "api_none.py").write_text("def tune(timeout: int | None = None) -> int:\n    return timeout + 1\n", encoding="utf-8")
    (repo / "recur.py").write_text(
        "class Node:\n"
        "    def walk(self, n: int) -> int:\n"
        "        if n <= 0:\n"
        "            return 0\n"
        "        return walk(n - 1)\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v2 breaks")

    dry = generate_fix_plan(repo, base_ref="v1.0", target_ref="HEAD", apply=False)
    assert dry.status == "ok" and dry.dry_run is True
    assert dry.safe_patches_count >= 2
    cats = {p.category for p in dry.patches}
    assert "caller_update" in cats
    assert "docstring_sync" in cats
    assert "none_guard" in cats
    assert "recursion_fix" in cats

    # Apply safe patches atomically
    applied = generate_fix_plan(repo, base_ref="v1.0", target_ref="HEAD", apply=True)
    assert applied.status == "ok" and applied.applied_count >= 2
    assert "max_retries=5" in (repo / "worker.py").read_text(encoding="utf-8")
    assert ":param max_retries:" in (repo / "api.py").read_text(encoding="utf-8")
    assert "if timeout is None:" in (repo / "api_none.py").read_text(encoding="utf-8")
    assert "return self.walk(n - 1)" in (repo / "recur.py").read_text(encoding="utf-8")

    # Verify CLI `athena fix --format diff` runs cleanly
    assert cli_main(["fix", str(repo), "--base", "v1.0", "--target", "HEAD", "--format", "diff"]) in (0, 1)


def test_remediation_overlap_conflict_and_path_escape_blocked(tmp_path: Path) -> None:
    from athena.remediation import FixEdit, FixPatch, _apply_patches_safely

    repo = tmp_path / "conflict_repo"
    _init_repo(repo)
    (repo / "mod.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")

    outside = tmp_path / "outside.py"
    outside.write_text("secret = 1\n", encoding="utf-8")

    p1 = FixPatch(
        fix_id="fix_001",
        symbol_name="x",
        file_path="mod.py",
        category="caller_update",
        applicability="safe",
        summary="edit 1",
        edits=[FixEdit(file_path="mod.py", start_line=1, end_line=1, original_text="x = 1", replacement_text="x = 10")],
    )
    p2_overlap = FixPatch(
        fix_id="fix_002",
        symbol_name="x",
        file_path="mod.py",
        category="caller_update",
        applicability="safe",
        summary="overlapping edit 2",
        edits=[FixEdit(file_path="mod.py", start_line=1, end_line=1, original_text="x = 1", replacement_text="x = 20")],
    )
    p3_escape = FixPatch(
        fix_id="fix_003",
        symbol_name="secret",
        file_path="../outside.py",
        category="caller_update",
        applicability="safe",
        summary="escape attempt",
        edits=[FixEdit(file_path="../outside.py", start_line=1, end_line=1, original_text="secret = 1", replacement_text="hacked = 1")],
    )

    applied, conflicts = _apply_patches_safely(repo, [p1, p2_overlap, p3_escape], include_review_required=False)
    assert applied == 1 and conflicts == 2
    assert p1.applied is True
    assert p2_overlap.applied is False and "Overlapping" in (p2_overlap.skipped_reason or "")
    assert p3_escape.applied is False and "Path safety check failed" in (p3_escape.skipped_reason or "")
    assert (repo / "mod.py").read_text(encoding="utf-8") == "x = 10\ny = 2\n"
    assert outside.read_text(encoding="utf-8") == "secret = 1\n"


def test_token_ledger_glob_bracket_paths_readonly_and_truncation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ATHENA_GAIN_DISABLE", raising=False)
    ledger_file = tmp_path / "ledger" / "gain.jsonl"
    monkeypatch.setenv("ATHENA_GAIN_LOG", str(ledger_file))

    proj_brackets = tmp_path / "ws" / "app[v2]" / "repo"
    proj_brackets.mkdir(parents=True)
    proj_other = tmp_path / "ws" / "other" / "repo"
    proj_other.mkdir(parents=True)

    rec1 = record_token_saving("map", proj_brackets, 10000, 1200, detail="ok")
    assert rec1["saved_chars"] == 8800 and rec1["expanded"] is False
    rec2 = record_token_saving("map", proj_other, 5000, 1000, detail="other")
    assert rec2["saved_chars"] == 4000
    rec_exp = record_token_saving("summary", proj_brackets, 100, 250)
    assert rec_exp["expanded"] is True and rec_exp["saved_chars"] == 0

    scoped = read_gain_report(proj_brackets)
    assert scoped["total_commands"] == 2
    assert scoped["expanded_count"] == 1
    assert scoped["total_saved_chars"] == 8800

    # Virtual path containing '*' and '?' glob characters must also filter cleanly without wildcard bleeding
    wildcard_proj = str(tmp_path / "ws" / "wild*?proj[1]")
    record_token_saving("map", wildcard_proj, 4000, 400)
    scoped_wild = read_gain_report(wildcard_proj)
    assert scoped_wild["total_commands"] == 1 and scoped_wild["total_saved_chars"] == 3600

    # Read-only / missing invalid log path degrades gracefully without raising
    bad_dir = tmp_path / "file_as_dir"
    bad_dir.write_text("block mkdir", encoding="utf-8")
    monkeypatch.setenv("ATHENA_GAIN_LOG", str(bad_dir / "nested" / "gain.jsonl"))
    res_graceful = record_token_saving("map", proj_brackets, 1000, 200)
    assert res_graceful["saved_chars"] == 800

    monkeypatch.setenv("ATHENA_GAIN_LOG", str(ledger_file))
    assert reset_gain_ledger()["cleared"] is True

    # Head+tail truncation preserves bottom errors and marks truncated=True
    long_text = ("HEADER_LINE\n" * 80) + "MIDDLE_NOISE\n" * 200 + "FATAL_TAIL_ERROR: assertion failed"
    trunc, was_trunc, omitted = truncate_head_tail(long_text, max_chars=400)
    assert was_trunc is True and omitted > 0
    assert "HEADER_LINE" in trunc and "FATAL_TAIL_ERROR: assertion failed" in trunc

    small = '{"status":"ok"}'
    chosen, did_compact = never_worse_payload(small, small + ',"extra_wrapper":true')
    assert chosen == small and did_compact is False


def test_mcp_15_tools_read_only_and_doctor_v133(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("ATHENA_GAIN_DISABLE", raising=False)
    monkeypatch.setenv("ATHENA_GAIN_LOG", str(tmp_path / "gain.jsonl"))

    async def _check() -> None:
        tools = await mcp_app.list_tools()
        names = {t.name for t in tools}
        assert len(tools) == 18
        assert len(_TOOL_CATALOG_METADATA) == 18
        assert "generate_fix_plan" in names
        assert "get_token_savings_report" in names

        ro = create_mcp_server(read_only=True)
        ro_names = {t.name for t in await ro.list_tools()}
        assert "generate_fix_plan" not in ro_names
        assert "get_token_savings_report" in ro_names

        res = await mcp_app.list_resources()
        uris = {str(r.uri) for r in res}
        assert "athena://gain/summary" in uris
        cap = json.loads(_extract_resource_text(await mcp_app.read_resource("athena://server/capabilities")))
        assert "treesitter" in cap
        gain_json = json.loads(_extract_resource_text(await mcp_app.read_resource("athena://gain/summary")))
        assert gain_json["status"] == "ok"

    asyncio.run(_check())

    assert cli_main(["doctor", "."]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["mcp"]["registered_tools"] == 18
    assert "treesitter" in doc
    assert "token_ledger" in doc
    assert doc["python"]["supported"] is True

    assert cli_main(["gain", "--all"]) == 0
    gain_out = json.loads(capsys.readouterr().out)
    assert gain_out["status"] == "ok"


def test_cpp_export_macro_and_overload_order_invariance(tmp_path: Path) -> None:
    repo = tmp_path / "cpp_macro_overload"
    _init_repo(repo)
    hdr = repo / "array.h"
    hdr.write_text(
        "class array {\n"
        " public:\n"
        "  explicit array(int x);\n"
        "  array(int x, int y);\n"
        "  int shape(int axis) const;\n"
        "  int dtype() const;\n"
        "};\n",
        encoding="utf-8",
    )
    cs_file = repo / "Agent.cs"
    cs_file.write_text(
        "using System.Threading.Tasks;\n"
        "public class Agent {\n"
        "  public Task InvokeAsync(string input) => Task.CompletedTask;\n"
        "  public Task InvokeAsync(string input, int maxTurns) => Task.CompletedTask;\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1")
    _git(repo, "tag", "v1.0")

    # Add export macro MLX_API on class + insert a new overload before existing constructors/methods
    hdr.write_text(
        "class MLX_API array {\n"
        " public:\n"
        "  array(double scalar, bool copy);\n"
        "  explicit array(int x);\n"
        "  array(int x, int y);\n"
        "  int shape(int axis) const;\n"
        "  int dtype() const;\n"
        "};\n",
        encoding="utf-8",
    )
    cs_file.write_text(
        "using System.Threading.Tasks;\n"
        "public class Agent {\n"
        "  public Task InvokeAsync(string input, bool stream) => Task.CompletedTask;\n"
        "  public Task InvokeAsync(string input) => Task.CompletedTask;\n"
        "  public Task InvokeAsync(string input, int maxTurns) => Task.CompletedTask;\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add export macro and insert new overloads")

    rep = run_breaking_change_detection(str(repo), base_ref="v1.0", target_ref="HEAD", use_llm=False)
    assert rep.status == "ok"
    assert rep.total_potential_breaking_changes == 0


def test_csharp_internal_enclosing_class_and_python_receiver_precision(tmp_path: Path) -> None:
    repo = tmp_path / "vis_and_recv"
    _init_repo(repo)
    (repo / "InternalActions.cs").write_text(
        "internal static class AgentThreadActions {\n"
        "  public static void CreateThreadAsync(string id) {}\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "src" / "mycli").mkdir(parents=True)
    (repo / "src" / "mycli" / "models.py").write_text(
        "class CLIModels:\n"
        "    def get(self, name: str) -> str:\n"
        "        return name\n",
        encoding="utf-8",
    )
    (repo / "src" / "mycli" / "_client.py").write_text(
        "class Client:\n"
        "    def copy(self, timeout: float) -> 'Client':\n"
        "        return self\n",
        encoding="utf-8",
    )
    (repo / "templates").mkdir()
    (repo / "templates" / "models.py").write_text(
        "def list_models(limit: int) -> list[str]:\n"
        "    return []\n",
        encoding="utf-8",
    )
    (repo / "caller.py").write_text(
        "import os as _os\n"
        "from copy import copy\n"
        "def boot(request, provider):\n"
        "    val = _os.environ.get('API_KEY')\n"
        "    dup = copy(request)\n"
        "    hdrs = request.headers.copy()\n"
        "    mods = provider.list_models(10)\n"
        "    return val, dup, hdrs, mods\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1")
    _git(repo, "tag", "v1.0")

    (repo / "InternalActions.cs").write_text(
        "internal static class AgentThreadActions {\n"
        "  public static void CreateThreadAsync(string id, bool force) {}\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "src" / "mycli" / "models.py").write_text("", encoding="utf-8")
    (repo / "src" / "mycli" / "_client.py").write_text(
        "class Client:\n"
        "    def copy(self, timeout: float, max_retries: int) -> 'Client':\n"
        "        return self\n",
        encoding="utf-8",
    )
    (repo / "templates" / "models.py").write_text("", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "break internal C#, client copy, CLI get, and template list_models")

    rep = run_breaking_change_detection(str(repo), base_ref="v1.0", target_ref="HEAD", use_llm=False)
    assert rep.status == "ok"
    by_sym = {f.affected_symbol: f for f in rep.potential_breaking_changes}
    assert "CreateThreadAsync" not in by_sym
    assert "CLIModels.get" not in by_sym or len(by_sym["CLIModels.get"].affected_callers) == 0
    assert "Client.copy" in by_sym and len(by_sym["Client.copy"].affected_callers) == 0
    if "list_models" in by_sym:
        assert len(by_sym["list_models"].affected_callers) == 0


def test_real_world_optional_params_pep585_java_cpp_swift_precision(tmp_path: Path) -> None:
    # 1. Python PEP 585 annotation modernization (Dict/List/Tuple/Optional -> dict/list/tuple) is non-breaking
    old_py = (
        "from typing import Dict, List, Optional, Tuple\n"
        "def model_dump(fields: Optional[Dict[str, str]] = None) -> Dict[str, List[Tuple[str, int]]]:\n"
        "    return {}\n"
    )
    new_py = (
        "def model_dump(fields: dict[str, str] | None = None) -> dict[str, list[tuple[str, int]]]:\n"
        "    return {}\n"
    )
    py_res = analyze_python_module_diff(old_py, new_py, file_path="main.py")
    assert all(not sc.is_breaking_candidate for sc in py_res.symbol_changes)

    # 2. Trailing optional params (PHP/TS), Java anonymous inner class + @Nullable,
    #    C++ internal dir/namespace + multiline template, and Swift @available/@_disfavoredOverload
    repo = tmp_path / "phase4_3_precision"
    _init_repo(repo)
    (repo / "Adapter.php").write_text(
        "<?php\nclass FilesystemAdapter {\n"
        "  public function copyToDisk($disk, $from, $to = null) { return true; }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "TreeRangeMap.java").write_text(
        "public class TreeRangeMap {\n"
        "  public Object remove(Object o) { return null; }\n"
        "  class SubRangeMap {\n"
        "    @Override public boolean equals(Object o) { return false; }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "absl" / "hash" / "internal").mkdir(parents=True)
    (repo / "absl" / "hash" / "internal" / "hash.h").write_text(
        "namespace absl { namespace hash_internal {\n"
        "template <typename T> void HelperInternal(T x);\n"
        "} }\n",
        encoding="utf-8",
    )
    (repo / "HTTPPipelineSetup.swift").write_text(
        "import NIOCore\n"
        "extension ChannelPipeline {\n"
        "  public func configureHTTPServerPipeline(position: Int = 0, pipelining: Bool = true) -> Int {\n"
        "    return position\n"
        "  }\n"
        "  public static func quic(requiredBytesHint: Int) -> Int { return requiredBytesHint }\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1")
    _git(repo, "tag", "v1.0")

    (repo / "Adapter.php").write_text(
        "<?php\nclass FilesystemAdapter {\n"
        "  public function copyToDisk($disk, $from, $to = null, $options = []) { return true; }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "TreeRangeMap.java").write_text(
        "public class TreeRangeMap {\n"
        "  public Object remove(@Nullable Object o) { return null; }\n"
        "  private static final Object EMPTY = new Object() {\n"
        "    @Override public boolean equals(@Nullable Object o) { return true; }\n"
        "  };\n"
        "  class SubRangeMap {\n"
        "    @Override public boolean equals(@Nullable Object o) { return false; }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "absl" / "hash" / "internal" / "hash.h").write_text("", encoding="utf-8")
    (repo / "HTTPPipelineSetup.swift").write_text(
        "import NIOCore\n"
        "extension ChannelPipeline {\n"
        "  @preconcurrency\n"
        '  @available(*, deprecated, message: "Use configureHTTPServerPipeline(position:) instead")\n'
        "  @_disfavoredOverload\n"
        "  public func configureHTTPServerPipeline(position: Int = 0, pipelining: Bool = true) -> Int {\n"
        "    return position\n"
        "  }\n"
        "  @inlinable\n"
        "  public static func quic(requiredBytesHint: Int) -> Int { return requiredBytesHint }\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "backwards-compatible updates and internal header removal")

    rep = run_breaking_change_detection(str(repo), base_ref="v1.0", target_ref="HEAD", use_llm=False)
    assert rep.status == "ok"
    assert rep.total_potential_breaking_changes == 0, (
        f"Unexpected breaking findings: {[f.affected_symbol for f in rep.potential_breaking_changes]}"
    )

    # 3. Swift & Scala files are indexed by CodeGraph + test_selector cleanly
    from athena.graph_store import build_code_graph

    (repo / "Tests" / "CoreTests").mkdir(parents=True)
    (repo / "Tests" / "CoreTests" / "PipelineTests.swift").write_text(
        "func testPipeline() { _ = configureHTTPServerPipeline() }\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add swift test")
    cg = build_code_graph(repo, persist=False, use_cache=False)
    swift_nodes = [n for n in cg.nodes if n.language == "swift"]
    assert any(n.label == "configureHTTPServerPipeline" for n in swift_nodes)
