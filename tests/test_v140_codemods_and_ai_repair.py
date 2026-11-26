"""Comprehensive v1.4.0 tests for multi-language codemods, Athena + AI bridge, and closed-loop verify-fix."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from athena import __version__
from athena.ai_providers import (
    AIRepairTask,
    _validate_and_convert_ai_edits,
    build_ai_repair_tasks,
    discover_ai_providers,
    invoke_ai_provider_for_task,
    resolve_ai_provider,
)
from athena.ast_analyzer import detect_python_doc_drift, run_structural_code_analysis
from athena.cli import main as cli_main
from athena.git_inspector import extract_revision_range_data, is_non_api_tooling_file
from athena.mcp_server import _TOOL_CATALOG_METADATA, create_mcp_server, mcp_app
from athena.remediation import generate_fix_plan
from athena.token_ledger import read_gain_report
from athena.treesitter_parser import extract_multilang_call_spans, is_treesitter_available
from athena.verify_fix import detect_available_toolchains, run_closed_loop_repair, verify_fix_state


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
    _git(repo, "config", "user.name", "Athena Test")
    _git(repo, "config", "user.email", "test@athena.local")


def _extract_resource_text(res_obj: object) -> str:
    if isinstance(res_obj, (str, bytes)):
        return res_obj.decode("utf-8") if isinstance(res_obj, bytes) else res_obj
    if isinstance(res_obj, list) and res_obj:
        first = res_obj[0]
        return str(getattr(first, "content", getattr(first, "text", first)))
    contents = getattr(res_obj, "contents", None)
    if contents:
        return str(getattr(contents[0], "text", contents[0]))
    return str(res_obj)


def _extract_tool_json(res_obj: object) -> dict:
    if isinstance(res_obj, dict):
        return res_obj
    if isinstance(res_obj, tuple):
        for part in reversed(res_obj):
            if isinstance(part, dict):
                return part
        if res_obj and isinstance(res_obj[0], list):
            return json.loads(str(getattr(res_obj[0][0], "text", res_obj[0][0])))
    if hasattr(res_obj, "structuredContent") and isinstance(res_obj.structuredContent, dict):
        return res_obj.structuredContent
    content = getattr(res_obj, "content", None)
    if content:
        return json.loads(str(getattr(content[0], "text", content[0])))
    raise AssertionError(f"Cannot extract JSON from tool output: {res_obj!r}")


def test_python_multiline_codemods_swaps_renames_docs_and_verify_fix(tmp_path: Path) -> None:
    repo = tmp_path / "py_multi_codemod"
    _init_repo(repo)
    (repo / "api.py").write_text(
        "def fetch_item(host: str, timeout: int = 5, retries: int = 2) -> str:\n"
        '    """Fetch item.\n\n'
        "    Args:\n"
        "        host (str): target host\n"
        "        timeout: request timeout\n"
        "        retries: retry attempts\n"
        '    """\n'
        "    return f'{host}:{timeout}:{retries}'\n\n"
        "def make_pair(first: str, second: int) -> str:\n"
        '    """Make pair.\n\n'
        "    Parameters\n"
        "    ----------\n"
        "    first : str\n"
        "        first element\n"
        "    second : int\n"
        "        second element\n"
        '    """\n'
        "    return f'{first}:{second}'\n\n"
        "def old_legacy(val: int) -> int:\n"
        "    return val + 1\n",
        encoding="utf-8",
    )
    (repo / "consumer.py").write_text(
        "from api import fetch_item, make_pair, old_legacy\n\n"
        "def run_calls() -> tuple[str, str, int]:\n"
        "    res = fetch_item(\n"
        "        'svc.local',\n"
        "        timeout=10,\n"
        "        retries=3,\n"
        "    )\n"
        "    pair = make_pair('alpha', 42)\n"
        "    num = old_legacy(9)\n"
        "    return res, pair, num\n",
        encoding="utf-8",
    )
    (repo / "test_consumer.py").write_text(
        "from consumer import run_calls\n\n"
        "def test_run_calls():\n"
        "    res, pair, num = run_calls()\n"
        "    assert res.startswith('svc.local:10')\n"
        "    assert pair == 'alpha:42'\n"
        "    assert num == 10\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1 baseline")
    _git(repo, "tag", "v1.0.0")

    # Introduce 4 real breaking changes in api.py while leaving consumer.py broken:
    # 1) timeout -> timeout_sec, drop optional retries
    # 2) make_pair swap (first, second) -> (second, first)
    # 3) rename old_legacy -> new_modern
    (repo / "api.py").write_text(
        "def fetch_item(host: str, timeout_sec: int = 5) -> str:\n"
        '    """Fetch item.\n\n'
        "    Args:\n"
        "        host (str): target host\n"
        "        timeout: request timeout\n"
        '    """\n'
        "    return f'{host}:{timeout_sec}:2'\n\n"
        "def make_pair(second: int, first: str) -> str:\n"
        '    """Make pair.\n\n'
        "    Parameters\n"
        "    ----------\n"
        "    second : int\n"
        "        second element\n"
        "    first : str\n"
        "        first element\n"
        '    """\n'
        "    return f'{first}:{second}'\n\n"
        "def new_modern(val: int) -> int:\n"
        "    return val + 1\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v2 breaking refactor")

    # Verify before fix: broken state MUST fail verification!
    pre_v = verify_fix_state(repo, base_ref="v1.0.0", target_ref="WORKING_TREE", run_typecheck=True, run_tests=True)
    assert pre_v.verified_ok is False

    # Docstring drift detects Google docstring param
    drift = detect_python_doc_drift((repo / "api.py").read_text(encoding="utf-8"), "api.py")
    assert any(d.referenced_symbol == "fetch_item" and "timeout" in d.snippet for d in drift)

    # Generate and apply deterministic mechanical fixes
    plan = generate_fix_plan(repo, base_ref="v1.0.0", target_ref="HEAD", apply=True)
    assert plan.status == "ok"
    assert plan.applied_count >= 4
    consumer_txt = (repo / "consumer.py").read_text(encoding="utf-8")
    assert "timeout_sec=10" in consumer_txt
    assert "retries=3" not in consumer_txt
    assert "make_pair(42, 'alpha')" in consumer_txt
    assert "new_modern(9)" in consumer_txt
    assert "from api import fetch_item, make_pair, new_modern" in consumer_txt
    api_txt = (repo / "api.py").read_text(encoding="utf-8")
    assert "timeout_sec: request timeout" in api_txt
    assert "def old_legacy(*args, **kwargs):" in api_txt

    v_after = verify_fix_state(repo, base_ref="v1.0.0", target_ref="WORKING_TREE", run_typecheck=True, run_tests=True)
    assert v_after.status == "ok"
    assert v_after.remaining_broken_callers_count == 0
    assert v_after.verified_ok is True
    assert any(r.tool == "python:py_compile" and r.status == "passed" for r in v_after.typecheck_results)
    assert any(r.tool == "pytest" and r.status == "passed" for r in v_after.test_results)


def test_non_api_tooling_files_suppressed_and_no_bogus_shims(tmp_path: Path) -> None:
    assert is_non_api_tooling_file("noxfile.py") is True
    assert is_non_api_tooling_file("scripts/release_tool.ts") is True
    assert is_non_api_tooling_file("benchmarks/bench_run.py") is True
    assert is_non_api_tooling_file("src/mylib/core.py") is False

    repo = tmp_path / "tooling_repo"
    _init_repo(repo)
    (repo / "noxfile.py").write_text("def test_pydantic_v1(session):\n    pass\n", encoding="utf-8")
    (repo / "scripts").mkdir()
    (repo / "scripts" / "gen.ts").write_text("export function buildDocs(x: number) { return x; }\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1")
    _git(repo, "tag", "v1")

    (repo / "noxfile.py").write_text("# removed old session\n", encoding="utf-8")
    (repo / "scripts" / "gen.ts").write_text("export {}\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v2 cleanup")

    ext = extract_revision_range_data(repo, base_ref="v1", target_ref="HEAD")
    analysis = run_structural_code_analysis(ext)
    assert all(sc.is_public_api_export is False and sc.api_surface == "internal_only" for sc in analysis.symbol_changes)

    plan = generate_fix_plan(repo, base_ref="v1", target_ref="HEAD", apply=False)
    assert all(p.category != "compat_shim" for p in plan.patches)


@pytest.mark.parametrize(
    "lang_case",
    [
        (
            "ts",
            "api.ts",
            "export function oldCalc(a: number, opt?: string): number { return a; }\n",
            "export function newCalc(a: number, opt?: string): number { return a; }\n",
            "caller.ts",
            "import { oldCalc } from './api';\nexport const v = oldCalc(1, 'hi');\n",
            "newCalc(1, 'hi')",
            True,
        ),
        (
            "go",
            "api.go",
            "package demo\nfunc OldFetch(id int) int {\n\treturn id\n}\n",
            "package demo\nfunc NewFetch(id int) int {\n\treturn id\n}\n",
            "caller.go",
            "package demo\nfunc Use() int {\n\treturn OldFetch(7)\n}\n",
            "NewFetch(7)",
            True,
        ),
        (
            "rust",
            "lib.rs",
            "pub fn old_parse(v: i32) -> i32 { v }\n",
            "pub fn new_parse(v: i32) -> i32 { v }\n",
            "main.rs",
            "fn run() -> i32 { old_parse(5) }\n",
            "new_parse(5)",
            True,
        ),
        (
            "java",
            "Api.java",
            "public class Api {\n  public static int oldSum(int x) { return x; }\n}\n",
            "public class Api {\n  public static int newSum(int x) { return x; }\n}\n",
            "App.java",
            "class App { int r = Api.oldSum(4); }\n",
            "Api.newSum(4)",
            False,
        ),
        (
            "csharp",
            "Client.cs",
            "public class Client {\n  public int Send(int timeout) { return timeout; }\n}\n",
            "public class Client {\n  public int Send(int timeoutSec) { return timeoutSec; }\n}\n",
            "Program.cs",
            "class Program { int f(Client c) { return c.Send(timeout: 9); } }\n",
            "c.Send(timeoutSec: 9)",
            False,
        ),
        (
            "kotlin",
            "Client.kt",
            "class Client {\n  fun runTask(timeout: Int): Int { return timeout }\n}\n",
            "class Client {\n  fun runTask(timeoutMs: Int): Int { return timeoutMs }\n}\n",
            "App.kt",
            "fun main(c: Client) { val r = c.runTask(timeout = 12) }\n",
            "c.runTask(timeoutMs = 12)",
            False,
        ),
        (
            "swift",
            "Client.swift",
            "public struct Client {\n  public func send(timeout: Int) -> Int { return timeout }\n}\n",
            "public struct Client {\n  public func send(timeoutSec: Int) -> Int { return timeoutSec }\n}\n",
            "App.swift",
            "func call(c: Client) -> Int { return c.send(timeout: 8) }\n",
            "c.send(timeoutSec: 8)",
            False,
        ),
        (
            "php",
            "Client.php",
            "<?php\nclass Client {\n  public function send(int $timeout): int { return $timeout; }\n}\n",
            "<?php\nclass Client {\n  public function send(int $limit): int { return $limit; }\n}\n",
            "app.php",
            "<?php\nfunction go(Client $c) { return $c->send(timeout: 3); }\n",
            "$c->send(limit: 3)",
            False,
        ),
    ],
)
def test_multilanguage_mechanical_codemods_generate_real_diffs(
    tmp_path: Path,
    lang_case: tuple[str, str, str, str, str, str, str, bool],
) -> None:
    label, def_file, old_def, new_def, call_file, caller_src, expected_sub, expect_shim = lang_case
    repo = tmp_path / f"ml_{label}"
    _init_repo(repo)
    (repo / def_file).write_text(old_def, encoding="utf-8")
    (repo / call_file).write_text(caller_src, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1")
    _git(repo, "tag", "v1")

    (repo / def_file).write_text(new_def, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v2")

    dry = generate_fix_plan(repo, base_ref="v1", target_ref="HEAD", apply=False)
    assert dry.status == "ok"
    caller_patches = [p for p in dry.patches if p.file_path == call_file and p.edits]
    assert caller_patches, f"Expected concrete FixEdit caller patch for {label}, got {dry.patches}"
    assert expected_sub in caller_patches[0].unified_diff
    if expect_shim:
        shims = [p for p in dry.patches if p.category == "compat_shim" and p.edits]
        assert shims and shims[0].unified_diff

    applied = generate_fix_plan(repo, base_ref="v1", target_ref="HEAD", apply=True)
    assert applied.applied_count >= 1
    assert expected_sub in (repo / call_file).read_text(encoding="utf-8")


def test_treesitter_call_spans_when_enabled() -> None:
    if not is_treesitter_available():
        pytest.skip("tree-sitter disabled or unavailable in this mode")
    spans = extract_multilang_call_spans(
        "func go(c: Client) {\n  c.send(timeout: 5, retries: 2)\n}\n",
        "App.swift",
        {"send"},
    )
    assert spans is not None and len(spans) == 1
    assert spans[0].callee_name == "send"
    assert [lbl for _, _, lbl in spans[0].arg_spans] == ["timeout", "retries"]


def test_ai_providers_security_discovery_and_mocked_transports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ATHENA_GAIN_LOG", str(tmp_path / "gain.jsonl"))
    secret_oa = "sk-proj-testsecret999999999999999999999999"
    secret_ant = "sk-ant-testsecret888888888888888888888888"
    monkeypatch.setenv("OPENAI_API_KEY", secret_oa)
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret_ant)

    def _offline_get(*args, **kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr("athena.ai_providers.httpx.get", _offline_get)
    providers = discover_ai_providers()
    serialized = json.dumps([p.model_dump(mode="json") for p in providers])
    assert secret_oa not in serialized
    assert secret_ant not in serialized
    assert any(p.provider == "handoff" and p.available for p in providers)
    assert any(p.provider == "openai-compat" and p.available for p in providers)
    assert any(p.provider == "anthropic" and p.available for p in providers)

    # Clear API keys + CLI tools -> auto resolves cleanly to handoff
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ATHENA_AI_API_KEY", raising=False)
    monkeypatch.delenv("ATHENA_AI_BASE_URL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr("athena.ai_providers.shutil.which", lambda _cmd: None)
    auto_res = resolve_ai_provider("auto")
    assert auto_res.provider == "handoff"

    # Prompt-injection path-jail enforcement & +-3 line snap
    repo = tmp_path / "ai_jail"
    _init_repo(repo)
    (repo / "caller.py").write_text("# hdr\nval = compute(1)\n", encoding="utf-8")
    (repo / "forbidden.py").write_text("SECRET = 1\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("OUT = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")

    task = AIRepairTask(
        task_id="task_001",
        finding_id="f1",
        symbol_name="compute",
        language_family="python",
        change_kind="signature_changed",
        definition_file="api.py",
        allowed_files=["caller.py"],
        instructions="update caller.py",
    )
    parsed = {
        "summary": "fix caller",
        "edits": [
            {"file_path": "../outside.py", "start_line": 1, "end_line": 1, "original_text": "OUT = 1", "replacement_text": "PWN = 1"},
            {"file_path": "forbidden.py", "start_line": 1, "end_line": 1, "original_text": "SECRET = 1", "replacement_text": "PWN = 1"},
            # Deliberately off by +2 lines (line 4 instead of line 2) to test +-3 snap
            {"file_path": "caller.py", "start_line": 4, "end_line": 4, "original_text": "val = compute(1)", "replacement_text": "val = compute(1, mode='v2')"},
        ],
    }
    patches = _validate_and_convert_ai_edits(repo, task, parsed, provider="ollama")
    assert len(patches) == 1
    assert patches[0].file_path == "caller.py"
    assert patches[0].edits[0].start_line == 2
    assert patches[0].source == "ai:ollama"

    # Mocked Ollama (<think> tag stripping), OpenAI-compat, Anthropic, and CLI subprocess adapters
    def _mock_ollama_get(url, **kwargs):
        return SimpleNamespace(status_code=200, json=lambda: {"models": [{"name": "qwen3:4b"}]})

    monkeypatch.setattr("athena.ai_providers.httpx.get", _mock_ollama_get)

    def _mock_http_post(url, **kwargs):
        good_json = json.dumps({
            "summary": "patched caller",
            "edits": [{"file_path": "caller.py", "start_line": 2, "end_line": 2, "original_text": "val = compute(1)", "replacement_text": "val = compute(1, mode='v2')"}],
        })
        if "/api/chat" in url:
            return SimpleNamespace(status_code=200, json=lambda: {"message": {"content": f"<think>reasoning</think>\n{good_json}"}})
        if "/chat/completions" in url:
            return SimpleNamespace(status_code=200, json=lambda: {"choices": [{"message": {"content": good_json}}]})
        return SimpleNamespace(status_code=200, json=lambda: {"content": [{"type": "text", "text": good_json}]})

    monkeypatch.setattr("athena.ai_providers.httpx.post", _mock_http_post)
    r_ol = invoke_ai_provider_for_task(repo, task, provider="ollama", model="qwen3:4b")
    assert r_ol.status == "ok" and len(r_ol.patches) == 1

    monkeypatch.setenv("OPENAI_API_KEY", secret_oa)
    r_oa = invoke_ai_provider_for_task(repo, task, provider="openai-compat")
    assert r_oa.status == "ok"

    monkeypatch.setenv("ANTHROPIC_API_KEY", secret_ant)
    r_ant = invoke_ai_provider_for_task(repo, task, provider="anthropic")
    assert r_ant.status == "ok"

    monkeypatch.setattr("athena.ai_providers.shutil.which", lambda cmd: f"/fake/bin/{cmd}")
    monkeypatch.setattr(
        "athena.ai_providers.subprocess.run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "result": json.dumps({
                    "summary": "cli patch",
                    "edits": [{"file_path": "caller.py", "start_line": 2, "end_line": 2, "original_text": "val = compute(1)", "replacement_text": "val = compute(1, mode='v2')"}],
                })
            }),
            stderr="",
        ),
    )
    for cli_prov in ("claude-code", "codex", "hermes", "pi", "cursor"):
        r_cli = invoke_ai_provider_for_task(repo, task, provider=cli_prov)
        assert r_cli.status == "ok" and r_cli.patches[0].source == f"ai:{cli_prov}"


def test_closed_loop_verify_fix_feedback_and_automatic_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ATHENA_GAIN_LOG", str(tmp_path / "gain.jsonl"))
    repo = tmp_path / "closed_loop"
    _init_repo(repo)
    (repo / "service.py").write_text("def compute(x: int) -> int:\n    return x * 2\n", encoding="utf-8")
    (repo / "client.py").write_text(
        "from service import compute\n\ndef run() -> int:\n    return compute(5)\n",
        encoding="utf-8",
    )
    (repo / "test_service.py").write_text(
        "from client import run\n\ndef test_run():\n    assert run() == 10\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1")
    _git(repo, "tag", "v1")

    # Semantic change: compute requires scaling factor `factor: int`
    (repo / "service.py").write_text(
        "def compute(x: int, factor: int) -> int:\n    return x * factor\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v2 require factor")

    # Check token ledger logs repair task compression cleanly in handoff mode
    dry_handoff = run_closed_loop_repair(repo, base_ref="v1", target_ref="HEAD", provider="handoff", apply=False)
    assert dry_handoff.status == "ok" and dry_handoff.dry_run is True
    assert len(dry_handoff.ai_repair_tasks) >= 1
    assert read_gain_report(repo)["total_commands"] >= 1

    # Simulate 2-iteration closed loop: iteration 1 proposes broken factor=99 (pytest fails),
    # iteration 2 receives failure feedback and repairs to factor=2 (pytest + py_compile + AST pass!)
    monkeypatch.setattr(
        "athena.verify_fix.resolve_ai_provider",
        lambda req, **kw: SimpleNamespace(provider="ollama", available=True, default_model="mock-coder"),
    )
    captured_feedback: list[str] = []

    def _two_step_ai(repo_root, task, *, provider, model, base_url, feedback, timeout_sec):
        from athena.ai_providers import AIProviderPatchResult
        from athena.remediation import FixEdit, FixPatch, _render_unified_diff

        captured_feedback.append(feedback)
        lines = (repo_root / "client.py").read_text(encoding="utf-8").splitlines()
        target_ln = next(i for i, l in enumerate(lines, 1) if "return compute(" in l)
        orig = lines[target_ln - 1]
        repl = "    return compute(5, 99)" if len(captured_feedback) == 1 else "    return compute(5, 2)"
        ed = FixEdit(file_path="client.py", start_line=target_ln, end_line=target_ln, original_text=orig, replacement_text=repl)
        pt = FixPatch(
            fix_id="ai_step",
            finding_id=task.finding_id,
            symbol_name=task.symbol_name,
            file_path="client.py",
            category="caller_update",
            applicability="review_required",
            summary="update call",
            edits=[ed],
            unified_diff=_render_unified_diff("client.py", lines, [ed]),
            source=f"ai:{provider}",
        )
        return AIProviderPatchResult(
            provider=provider,
            model=model,
            task_id=task.task_id,
            status="ok",
            summary=pt.summary,
            patches=[pt],
        )

    monkeypatch.setattr("athena.verify_fix.invoke_ai_provider_for_task", _two_step_ai)
    loop_res = run_closed_loop_repair(
        repo,
        base_ref="v1",
        target_ref="HEAD",
        provider="ollama",
        apply=True,
        max_iterations=2,
        rollback_on_fail=True,
    )
    assert loop_res.status == "ok"
    assert loop_res.verified_ok is True
    assert loop_res.rolled_back is False
    assert len(loop_res.iterations) == 2
    assert "Tests `pytest` failed" in captured_feedback[1] or "99" in captured_feedback[1]
    assert "return compute(5, 2)" in (repo / "client.py").read_text(encoding="utf-8")

    # Now test automatic rollback when AI keeps failing through max_iterations
    _git(repo, "checkout", "--", "client.py")

    def _always_bad_ai(repo_root, task, *, provider, model, base_url, feedback, timeout_sec):
        from athena.ai_providers import AIProviderPatchResult
        from athena.remediation import FixEdit, FixPatch, _render_unified_diff

        lines = (repo_root / "client.py").read_text(encoding="utf-8").splitlines()
        target_ln = next(i for i, l in enumerate(lines, 1) if "return compute(" in l)
        ed = FixEdit(file_path="client.py", start_line=target_ln, end_line=target_ln, original_text=lines[target_ln - 1], replacement_text="    return compute(5, 999)")
        pt = FixPatch(
            fix_id="bad_step",
            finding_id=task.finding_id,
            symbol_name=task.symbol_name,
            file_path="client.py",
            category="caller_update",
            applicability="review_required",
            summary="bad",
            edits=[ed],
            unified_diff=_render_unified_diff("client.py", lines, [ed]),
            source=f"ai:{provider}",
        )
        return AIProviderPatchResult(
            provider=provider,
            model=model,
            task_id=task.task_id,
            status="ok",
            summary="bad",
            patches=[pt],
        )

    monkeypatch.setattr("athena.verify_fix.invoke_ai_provider_for_task", _always_bad_ai)
    fail_res = run_closed_loop_repair(
        repo,
        base_ref="v1",
        target_ref="HEAD",
        provider="ollama",
        apply=True,
        max_iterations=2,
        rollback_on_fail=True,
    )
    assert fail_res.status == "ok"
    assert fail_res.verified_ok is False
    assert fail_res.rolled_back is True
    assert "return compute(5)" in (repo / "client.py").read_text(encoding="utf-8")


def test_cli_verify_fix_repair_doctor_and_mcp_v140(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ATHENA_GAIN_LOG", str(tmp_path / "gain.jsonl"))
    repo = tmp_path / "cli_mcp_v140"
    _init_repo(repo)
    (repo / "lib.py").write_text("def greet(name: str) -> str:\n    return f'hi {name}'\n", encoding="utf-8")
    (repo / "test_lib.py").write_text("from lib import greet\n\ndef test_g():\n    assert greet('a') == 'hi a'\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v1")
    _git(repo, "tag", "v1")
    (repo / "lib.py").write_text("def greet(name: str, exclaim: bool = False) -> str:\n    return f'hi {name}!' if exclaim else f'hi {name}'\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "v2")

    assert __version__ == "1.4.0"
    assert detect_available_toolchains(repo)["available"]["python"] is True

    assert cli_main(["doctor", str(repo)]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["mcp"]["registered_tools"] == 18
    assert "ai_providers" in doc and "toolchains" in doc

    assert cli_main(["verify-fix", str(repo), "--base", "v1"]) == 0
    vf_out = json.loads(capsys.readouterr().out)
    assert vf_out["verified_ok"] is True

    assert cli_main(["repair", str(repo), "--base", "v1", "--provider", "handoff"]) == 0
    rep_out = json.loads(capsys.readouterr().out)
    assert rep_out["provider_used"] == "handoff" and rep_out["dry_run"] is True

    async def _check_mcp() -> None:
        tools = await mcp_app.list_tools()
        names = {t.name for t in tools}
        assert len(tools) == 18 and len(_TOOL_CATALOG_METADATA) == 18
        assert {"prepare_ai_repair_tasks", "verify_fix", "run_ai_repair"}.issubset(names)

        ro = create_mcp_server(read_only=True)
        ro_names = {t.name for t in await ro.list_tools()}
        assert "run_ai_repair" not in ro_names
        assert {"prepare_ai_repair_tasks", "verify_fix"}.issubset(ro_names)

        res_uris = {str(r.uri) for r in await mcp_app.list_resources()}
        assert "athena://ai/providers" in res_uris
        prov_json = json.loads(_extract_resource_text(await mcp_app.read_resource("athena://ai/providers")))
        assert prov_json["status"] == "ok" and "supported_providers" in prov_json

        prompts = {p.name for p in await mcp_app.list_prompts()}
        assert "guided_breaking_fix" in prompts

        prep = _extract_tool_json(
            await mcp_app.call_tool("prepare_ai_repair_tasks", {"repo_path": str(repo), "base_ref": "v1", "target_ref": "HEAD"})
        )
        assert prep["status"] == "ok"

        vf_mcp = _extract_tool_json(
            await mcp_app.call_tool("verify_fix", {"repo_path": str(repo), "base_ref": "v1", "target_ref": "WORKING_TREE"})
        )
        assert vf_mcp["status"] == "ok" and vf_mcp["verified_ok"] is True

    asyncio.run(_check_mcp())
