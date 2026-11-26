"""Comprehensive tests for Athena v1.3.2 MCP 2026 capabilities and CLI fixes."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from athena import __version__
from athena.cli import main as cli_main
from athena.debt_tracker import scan_shortcut_debt
from athena.evidence_store import EvidenceStore
from athena.mcp_server import (
    VALID_TOOLSETS,
    create_mcp_server,
    detect_potential_breaking_changes,
    get_repo_map_tool,
    inspect_repository,
    mcp_app,
    run_mcp_server,
)
from athena.security import AthenaValidationError
from athena.test_selector import predict_affected_tests


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _extract_resource_text(res: Any) -> str:
    if isinstance(res, str):
        return res
    contents = getattr(res, "contents", res)
    if isinstance(contents, tuple):
        contents = list(contents)
    if isinstance(contents, list) and contents:
        first = contents[0]
        if isinstance(first, str):
            return first
        if hasattr(first, "content"):
            return str(first.content)
        if hasattr(first, "text"):
            return str(first.text)
    if hasattr(contents, "content"):
        return str(contents.content)
    if hasattr(contents, "text"):
        return str(contents.text)
    raise AssertionError(f"Unexpected resource response: {res!r}")


def _extract_tool_json(res: Any) -> dict[str, Any]:
    if isinstance(res, dict):
        return res
    if hasattr(res, "structuredContent") and isinstance(res.structuredContent, dict):
        return res.structuredContent
    if hasattr(res, "content") and res.content:
        return json.loads(res.content[0].text)
    if isinstance(res, tuple) and res[0]:
        return json.loads(res[0][0].text)
    raise AssertionError(f"Unexpected tool response: {res!r}")


@pytest.fixture()
def sample_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "v132_repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir(parents=True)
    _git(repo, "init")
    _git(repo, "config", "user.name", "Tester")
    _git(repo, "config", "user.email", "tester@example.com")

    (repo / "src" / "billing.py").write_text(
        "def charge(amount: int, currency: str = 'USD') -> int:\n"
        "    # shortcut: in-memory ledger, migrate to SQLite at 10k tx\n"
        "    return amount\n\n"
        "def helper_a() -> int:\n"
        "    # shortcut: quick heuristic\n"
        "    return 1\n\n"
        "def helper_b() -> int:\n"
        "    # shortcut: fixed retry, add backoff at v2\n"
        "    return 2\n\n"
        "def helper_c() -> int:\n"
        "    # shortcut: linear search\n"
        "    return 3\n",
        encoding="utf-8",
    )
    (repo / "src" / "orders.py").write_text(
        "def submit_order(order_id: int) -> bool:\n"
        "    return order_id > 0\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_billing.py").write_text(
        "from src.billing import charge\n\ndef test_charge():\n    assert charge(5) == 5\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_billing_edge.py").write_text(
        "from src.billing import charge\n\ndef test_charge_edge():\n    assert charge(1) == 1\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_orders.py").write_text(
        "from src.orders import submit_order\n\ndef test_orders():\n    assert submit_order(1)\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat: initial v1")
    _git(repo, "tag", "v1.0.0")

    (repo / "src" / "billing.py").write_text(
        "def charge(amount: int) -> int:\n"
        "    # shortcut: in-memory ledger, migrate to SQLite at 10k tx\n"
        "    return amount\n\n"
        "def helper_a() -> int:\n"
        "    # shortcut: quick heuristic\n"
        "    return 1\n\n"
        "def helper_b() -> int:\n"
        "    # shortcut: fixed retry, add backoff at v2\n"
        "    return 2\n\n"
        "def helper_c() -> int:\n"
        "    # shortcut: linear search\n"
        "    return 3\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "refactor: drop currency parameter")
    _git(repo, "tag", "v1.1.0")
    return repo


def test_evidence_store_disk_persistence_pruning_and_security(tmp_path: Path) -> None:
    ev_dir = tmp_path / "evidence_store"
    writer = EvidenceStore(max_entries=2, persist_dir=ev_dir)
    s1 = writer.retain("bundle_a", {"rows": list(range(10))}, completeness="complete")
    s2 = writer.retain("bundle_b", {"rows": list(range(20))}, completeness="complete")
    ev1 = s1["parent_evidence_id"]
    ev2 = s2["parent_evidence_id"]

    # New process-equivalent store instance reads retained bundle from disk
    reader = EvidenceStore(max_entries=2, persist_dir=ev_dir)
    assert reader.has(ev1) is True
    assert reader.has(ev2) is True
    page = reader.inspect_view(ev1, "rows", offset=5, limit=3)
    assert page["status"] == "ok" and page["items"] == [5, 6, 7] and page["has_more"] is True

    # Anti-traversal & pagination argument validation
    bad = reader.inspect_view("ev_../../secret", "rows")
    assert bad["status"] == "error" and bad["error_code"] == "EVIDENCE_NOT_FOUND"
    assert bad["retryable"] is True and bad["remediation_action"]

    bad_off = reader.inspect_view(ev1, "rows", offset=-1)
    assert bad_off["status"] == "error" and bad_off["error_code"] == "INVALID_OFFSET"
    assert bad_off["retryable"] is False and bad_off["remediation_action"]

    bad_lim = reader.inspect_view(ev1, "rows", limit=0)
    assert bad_lim["status"] == "error" and bad_lim["error_code"] == "INVALID_LIMIT"
    assert bad_lim["retryable"] is False and bad_lim["remediation_action"]

    # LRU pruning removes oldest file when exceeding max_entries=2
    s3 = writer.retain("bundle_c", {"rows": list(range(30))}, completeness="complete")
    ev3 = s3["parent_evidence_id"]
    assert ev3.startswith("ev_")
    assert len(list(ev_dir.glob("ev_*.json"))) == 2


def test_cross_process_cli_summary_and_view_roundtrip(
    sample_repo: Path,
    tmp_path: Path,
) -> None:
    ev_dir = tmp_path / "cli_evidence"
    env = {**os.environ, "ATHENA_EVIDENCE_DIR": str(ev_dir)}

    p_brk = subprocess.run(
        [
            sys.executable,
            "-m",
            "athena",
            "breaking-changes",
            str(sample_repo),
            "--base",
            "v1.0.0",
            "--target",
            "v1.1.0",
            "--detail",
            "summary",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert p_brk.returncode == 0, p_brk.stderr
    brk_summary = json.loads(p_brk.stdout)
    ev_id = brk_summary["parent_evidence_id"]
    assert ev_id.startswith("ev_")

    # Separate subprocess reads persisted evidence via `athena view`
    p_view = subprocess.run(
        [
            sys.executable,
            "-m",
            "athena",
            "view",
            ev_id,
            "--facet",
            "potential_breaking_changes",
            "--offset",
            "0",
            "--limit",
            "5",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert p_view.returncode == 0, p_view.stdout + p_view.stderr
    viewed = json.loads(p_view.stdout)
    assert viewed["status"] == "ok"
    assert viewed["total"] >= 1
    assert any(item["affected_symbol"] == "charge" for item in viewed["items"])

    # Also verify `athena analyze --detail summary` and `athena graph --detail summary`
    p_an = subprocess.run(
        [
            sys.executable,
            "-m",
            "athena",
            "analyze",
            str(sample_repo),
            "--base",
            "v1.0.0",
            "--target",
            "v1.1.0",
            "--detail",
            "summary",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert p_an.returncode == 0
    assert json.loads(p_an.stdout)["parent_evidence_id"].startswith("ev_")


def test_validation_fixes_and_bounded_pagination(
    sample_repo: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # map --max-chars <= 0 must reject with non-zero exit code & structured error
    assert cli_main(["map", str(sample_repo), "--max-chars", "-10"]) == 2
    err_map = json.loads(capsys.readouterr().out)
    assert err_map["status"] == "error" and err_map["error_code"] == "INVALID_MAX_CHARS"

    mcp_err = get_repo_map_tool(str(sample_repo), max_chars=0)
    assert mcp_err["status"] == "error"
    assert mcp_err["error_code"] == "INVALID_MAX_CHARS"
    assert mcp_err["retryable"] is False
    assert mcp_err["remediation_action"]

    # Bounded pagination on debt tracker
    full_debt = scan_shortcut_debt(sample_repo)
    assert full_debt.total_shortcuts == 4
    page1 = scan_shortcut_debt(sample_repo, offset=1, limit=2)
    assert len(page1.items) == 2
    assert page1.total_items == 4
    assert page1.has_more is True and page1.partial is True
    assert page1.items == full_debt.items[1:3]

    assert cli_main(["debt", str(sample_repo), "--offset", "0", "--limit", "2"]) == 0
    cli_debt = json.loads(capsys.readouterr().out)
    assert len(cli_debt["items"]) == 2 and cli_debt["has_more"] is True

    assert cli_main(["debt", str(sample_repo), "--limit", "0"]) == 2
    capsys.readouterr()

    # Bounded pagination on affected-tests
    full_tests = predict_affected_tests(sample_repo, base_ref="v1.0.0", target_ref="v1.1.0")
    assert full_tests["selected_count"] == 2
    paged_tests = predict_affected_tests(
        sample_repo,
        base_ref="v1.0.0",
        target_ref="v1.1.0",
        offset=0,
        limit=1,
    )
    assert paged_tests["returned_count"] == 1
    assert paged_tests["selected_count"] == 2
    assert paged_tests["has_more"] is True and paged_tests["partial"] is True

    assert cli_main(["affected-tests", str(sample_repo), "--base", "v1.0.0", "--target", "v1.1.0", "--limit", "1"]) == 0
    cli_tests = json.loads(capsys.readouterr().out)
    assert len(cli_tests["selected_tests"]) == 1 and cli_tests["has_more"] is True


def test_mcp_resources_prompts_toolsets_titles_and_transport_guards(
    sample_repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ATHENA_EVIDENCE_DIR", str(tmp_path / "mcp_ev"))

    async def _run() -> None:
        tools = await mcp_app.list_tools()
        assert len(tools) == 15
        supports_title = "title" in inspect.signature(mcp_app.tool).parameters
        if supports_title:
            for tool in tools:
                assert tool.title, f"Tool {tool.name} missing human-friendly title"

        resources = await mcp_app.list_resources()
        res_uris = {str(r.uri) for r in resources}
        assert {
            "athena://server/capabilities",
            "athena://repo/map",
            "athena://evidence/recent",
        }.issubset(res_uris)

        templates = await mcp_app.list_resource_templates()
        tpl_uris = {getattr(t, "uri_template", getattr(t, "uriTemplate", "")) for t in templates}
        assert "athena://evidence/{evidence_id}" in tpl_uris

        cap_data = json.loads(_extract_resource_text(await mcp_app.read_resource("athena://server/capabilities")))
        assert cap_data["version"] == __version__
        assert cap_data["active_toolsets"] == list(VALID_TOOLSETS)

        # Retain an evidence bundle and read it via resource + alias detail='summary'
        alias_sum = _extract_tool_json(
            await mcp_app.call_tool(
                "verify_breaking_and_doc_drift",
                {
                    "repo_path": str(sample_repo),
                    "base_ref": "v1.0.0",
                    "head_ref": "v1.1.0",
                    "enable_llm_behavioral_pass": False,
                    "detail": "summary",
                },
            )
        )
        ev_id = alias_sum["parent_evidence_id"]
        assert ev_id.startswith("ev_")

        hist_sum = _extract_tool_json(
            await mcp_app.call_tool(
                "analyze_change_graph",
                {
                    "repo_path": str(sample_repo),
                    "base_ref": "v1.0.0",
                    "head_ref": "v1.1.0",
                    "use_llm": False,
                    "detail": "summary",
                },
            )
        )
        assert hist_sum["parent_evidence_id"].startswith("ev_")

        recent_ev = json.loads(_extract_resource_text(await mcp_app.read_resource("athena://evidence/recent")))
        assert any(b["evidence_id"] == ev_id for b in recent_ev["bundles"])

        bundle_detail = json.loads(_extract_resource_text(await mcp_app.read_resource(f"athena://evidence/{ev_id}")))
        assert bundle_detail["status"] == "ok" and bundle_detail["evidence_id"] == ev_id

        prompts = await mcp_app.list_prompts()
        assert {p.name for p in prompts} == {
            "pre_merge_audit",
            "release_readiness_review",
            "codebase_onboarding",
        }
        prompt_res = await mcp_app.get_prompt(
            "pre_merge_audit",
            {"repo_path": str(sample_repo), "base_ref": "v1.0.0", "target_ref": "v1.1.0"},
        )
        assert "detect_potential_breaking_changes" in prompt_res.messages[0].content.text

        # Toolset & read-only scoping
        scoped = create_mcp_server(toolsets="git,graph", read_only=True)
        scoped_names = {t.name for t in await scoped.list_tools()}
        assert scoped_names == {"inspect_repository", "get_repo_map", "query_code_graph"}

        ro_release = create_mcp_server(toolsets="release", read_only=True)
        assert len(await ro_release.list_tools()) == 0

    asyncio.run(_run())

    # Unknown toolset fails validation explicitly
    with pytest.raises(AthenaValidationError) as exc_info:
        create_mcp_server(toolsets="nonexistent_set")
    assert exc_info.value.code == "INVALID_TOOLSET"

    # Loopback security blocks non-localhost bind without allow_remote=True
    with pytest.raises(AthenaValidationError) as net_exc:
        run_mcp_server(transport="streamable-http", host="0.0.0.0", port=8765)
    assert net_exc.value.code == "REMOTE_BIND_BLOCKED"

    # Invalid transport fails explicitly
    with pytest.raises(AthenaValidationError) as tr_exc:
        run_mcp_server(transport="ws")
    assert tr_exc.value.code == "INVALID_TRANSPORT"

    # Downstream engine errors must also carry structured recovery fields
    bad_insp = inspect_repository(str(tmp_path / "does_not_exist_xyz"))
    assert bad_insp["status"] == "error"
    assert bad_insp["error_code"] == "REPO_PATH_NOT_FOUND"
    assert bad_insp["error_kind"] == "validation"
    assert bad_insp["retryable"] is False
    assert bad_insp["remediation_action"]

    bad_ref = detect_potential_breaking_changes(str(sample_repo), base_ref="NO_SUCH_REF_XYZ")
    assert bad_ref["status"] == "error"
    assert bad_ref["error_code"] == "REVISION_NOT_FOUND"
    assert bad_ref["retryable"] is False
    assert bad_ref["remediation_action"]

    # Real ASGI streamable-http JSON-RPC round-trip (MCP 2.x)
    if hasattr(mcp_app, "streamable_http_app"):
        http_params = inspect.signature(mcp_app.streamable_http_app).parameters
        kwargs = {
            k: v
            for k, v in {"stateless_http": True, "json_response": True}.items()
            if k in http_params
        }

        async def _http_check() -> None:
            app = mcp_app.streamable_http_app(**kwargs)
            headers = {"Accept": "application/json, text/event-stream"}
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="http://127.0.0.1:8765",
                ) as client:
                    r_init = await client.post(
                        "/mcp",
                        headers=headers,
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2025-03-26",
                                "capabilities": {},
                                "clientInfo": {"name": "pytest-http", "version": "1.0"},
                            },
                        },
                    )
                    assert r_init.status_code == 200
                    r_tools = await client.post(
                        "/mcp",
                        headers=headers,
                        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                    )
                    assert r_tools.status_code == 200
                    assert len(r_tools.json()["result"]["tools"]) == 15
                    r_res = await client.post(
                        "/mcp",
                        headers=headers,
                        json={"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
                    )
                    assert r_res.status_code == 200
                    assert len(r_res.json()["result"]["resources"]) >= 3
                    r_prm = await client.post(
                        "/mcp",
                        headers=headers,
                        json={"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}},
                    )
                    assert r_prm.status_code == 200
                    assert len(r_prm.json()["result"]["prompts"]) == 3

        asyncio.run(_http_check())


def test_cli_doctor_and_scoped_stdio_session(
    sample_repo: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli_main(["doctor", str(sample_repo)]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["athena_version"] == __version__
    assert doc["git"]["available"] is True
    assert doc["mcp"]["registered_tools"] == 15
    assert doc["repository"]["is_valid_git_repo"] is True

    async def _stdio_check() -> None:
        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "athena", "mcp", "--toolsets", "git,graph,evidence", "--read-only"],
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools_res = await session.list_tools()
                names = {t.name for t in tools_res.tools}
                assert names == {
                    "inspect_repository",
                    "get_repo_map",
                    "query_code_graph",
                    "inspect_analysis_view",
                }
                prompts_res = await session.list_prompts()
                assert len(prompts_res.prompts) == 3
                res_list = await session.list_resources()
                assert len(res_list.resources) >= 3

    asyncio.run(_stdio_check())


def test_large_hunk_diff_parsing_and_redaction_bounds() -> None:
    from athena.git_inspector import MAX_EVIDENCE_EXCERPT_CHARS, _parse_unified_diff_by_file

    giant_hunks = ["diff --git a/big.json b/big.json\nindex 111..222 100644\n--- a/big.json\n+++ b/big.json\n"]
    for idx in range(12):
        tok_line = '+token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"\n' if idx == 0 else "+data = 1\n"
        filler = "".join(f"+row_{idx}_{j} = 'ok'\n" for j in range(180))
        giant_hunks.append(f"@@ -{idx * 200 + 1},5 +{idx * 200 + 1},181 @@\n{tok_line}{filler}")

    parsed = _parse_unified_diff_by_file("".join(giant_hunks))
    hunks, ins, dels, is_bin = parsed["big.json"]
    assert not is_bin and ins > 1000 and dels == 0
    assert len(hunks) == 12
    assert len(hunks[0].excerpt) <= MAX_EVIDENCE_EXCERPT_CHARS + 32
    assert "ghp_" not in hunks[0].excerpt
    assert hunks[11].excerpt == ""


def test_evidence_store_prune_path_confinement_and_asset_secret_redaction(tmp_path: Path) -> None:
    import importlib.util

    from athena.evidence_store import EvidenceStore

    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    decoy = ev_dir / "ev_custom_note.json"
    decoy.write_text('{"keep": true}', encoding="utf-8")

    store = EvidenceStore(max_entries=2, persist_dir=ev_dir)
    for i in range(4):
        store.retain("graph_query", {"status": "ok", "seq": i})

    canonical_files = [
        p for p in ev_dir.glob("ev_*.json") if p != decoy
    ]
    assert len(canonical_files) == 2
    assert decoy.exists(), "Non-canonical file must never be unlinked during LRU pruning"

    script_path = Path(__file__).resolve().parents[1] / "scripts" / "update_readme_assets.py"
    spec = importlib.util.spec_from_file_location("update_readme_assets", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    raw_tok = "tok_custom_987654321"
    leaked = (
        f"{raw_tok} "
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 "
        "github_pat_1234567890abcdefghij123456 "
        "Authorization: Bearer super_secret_token "
        "https://alice:s3cr3tpass@example.com/path?token=abc123&ok=1"
    )
    redacted = mod._redact_secrets(leaked, (raw_tok,))
    assert raw_tok not in redacted
    assert "ghp_" not in redacted
    assert "github_pat_" not in redacted
    assert "super_secret_token" not in redacted
    assert "alice:s3cr3tpass" not in redacted
    assert "abc123" not in redacted

    with pytest.raises(ValueError, match="non-GitHub API"):
        mod._github_get_json("https://evil.example/repos", "application/json", raw_tok)
