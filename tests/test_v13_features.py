"""Comprehensive tests for Athena v1.3.0 features (Graph, Map, Debt, EvidenceStore, Installer, MCP)."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from athena import __version__
from athena.agent_installer import SUPPORTED_AGENTS, install_agent_integration
from athena.cli import main as cli_main
from athena.debt_tracker import scan_shortcut_debt
from athena.evidence_store import (
    AnalysisResourceConstraintError,
    EvidenceStore,
    canonical_evidence_id,
    canonical_unknown_id,
    resolve_completeness,
)
from athena.graph_query import (
    get_god_nodes,
    get_graph_stats,
    query_code_graph,
    shortest_path_between,
)
from athena.graph_store import build_code_graph, load_code_graph
from athena.mcp_server import mcp_app
from athena.repo_map import build_repo_map


def _init_git_repo(root: Path) -> None:
    subprocess.run(["git", "init"], cwd=str(root), check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(root), check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=str(root), check=True, capture_output=True, text=True)


@pytest.fixture()
def polyglot_repo(tmp_path: Path) -> Path:
    """Create a realistic polyglot Git repository with core, tests, dynamic dispatch, and shortcut debt."""
    repo = tmp_path / "poly_repo"
    (repo / "src" / "core").mkdir(parents=True)
    (repo / "src" / "web").mkdir(parents=True)
    (repo / "tests").mkdir(parents=True)

    (repo / "src" / "core" / "auth.py").write_text(
        "def verify_token(token: str) -> bool:\n"
        "    # shortcut: linear scan of revoked tokens, upgrade to Redis set at 10k users\n"
        "    return bool(token)\n\n"
        "def dispatch_action(obj, name: str):\n"
        "    # shortcut: quick dynamic lookup\n"
        "    fn = getattr(obj, name)\n"
        "    return fn()\n",
        encoding="utf-8",
    )
    (repo / "src" / "core" / "service.py").write_text(
        "from src.core.auth import verify_token\n\n"
        "class AuthService:\n"
        "    def authenticate(self, tok: str) -> bool:\n"
        "        return verify_token(tok)\n",
        encoding="utf-8",
    )
    (repo / "src" / "web" / "client.ts").write_text(
        "export function verify_token(tok: string): boolean {\n"
        "  return tok.length > 0;\n"
        "}\n"
        "export class WebClient {\n"
        "  login(tok: string): boolean { return verify_token(tok); }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_auth.py").write_text(
        "def _make_user():\n"
        "    return {'id': 1}\n\n"
        "def test_ok():\n"
        "    u = _make_user()\n"
        "    assert u['id'] == 1\n",
        encoding="utf-8",
    )

    _init_git_repo(repo)
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), check=True, capture_output=True, text=True)
    return repo


def test_version_is_1_3_x() -> None:
    assert __version__ == "1.3.2"


def test_evidence_store_canonical_ids_and_paging() -> None:
    id1 = canonical_evidence_id({"a": 1, "b": [2, 3], "caller_input_path": "/tmp/x"})
    id2 = canonical_evidence_id({"b": [2, 3], "a": 1, "caller_input_path": "/var/y"})
    assert id1.startswith("ev_") and id1 == id2

    unk = canonical_unknown_id({"kind": "dynamic_dispatch", "file": "a.py", "line": 10})
    assert unk.startswith("unk_")

    assert resolve_completeness() == "complete"
    assert resolve_completeness(skipped_files=1) == "partial"
    assert resolve_completeness(unresolved_unknowns=2) == "partial"
    assert resolve_completeness(parse_errors=1) == "partial"

    err = AnalysisResourceConstraintError("memory", "Too large", remediation_action="Set max_commits=50")
    d = err.to_dict()
    assert d["error_kind"] == "resource_constraint" and d["retryable"] is True

    store = EvidenceStore(max_entries=4)
    summary = store.retain(
        "test_bundle",
        {"items": list(range(15)), "meta": {"ok": True}},
        completeness="complete",
    )
    ev_id = summary["parent_evidence_id"]
    assert ev_id.startswith("ev_")
    page1 = store.inspect_view(ev_id, "items", offset=0, limit=5)
    assert page1["status"] == "ok"
    assert page1["items"] == [0, 1, 2, 3, 4]
    assert page1["has_more"] is True

    page3 = store.inspect_view(ev_id, "items", offset=10, limit=5)
    assert page3["items"] == [10, 11, 12, 13, 14]
    assert page3["has_more"] is False


def test_code_graph_build_query_god_nodes_and_incremental_cache(polyglot_repo: Path) -> None:
    cg = build_code_graph(polyglot_repo, persist=True, use_cache=True)
    assert cg.total_files_scanned == 4
    assert cg.completeness == "partial"  # because getattr creates a ResidualUnknown
    assert any(u.kind == "dynamic_dispatch" for u in cg.unknowns)
    assert (polyglot_repo / ".athena" / "graph.json").is_file()
    assert (polyglot_repo / ".athena" / "graph_cache.json").is_file()

    # Non-test god nodes must not include _make_user or test_ok
    gods = get_god_nodes(cg, limit=10, include_tests=False)
    god_labels = {g["label"] for g in gods}
    assert "_make_user" not in god_labels
    assert "test_ok" not in god_labels

    # Cross-language isolation: Python service.py must not link to TS verify_token
    ts_verify = next(n for n in cg.nodes if n.file_path.endswith("client.ts") and n.label == "verify_token")
    py_service = next(n for n in cg.nodes if n.file_path.endswith("service.py") and n.kind == "module")
    assert not any(e.source == py_service.id and e.target == ts_verify.id for e in cg.edges)

    # Query graph respects token budget
    qres = query_code_graph(cg, "verify_token authenticate", depth=2, token_budget=500)
    assert qres["status"] == "ok"
    assert qres["estimated_tokens"] <= 500
    assert any("verify_token" in n["label"] for n in qres["subgraph_nodes"])

    # Shortest path & stats
    sp = shortest_path_between(cg, "AuthService.authenticate", "AuthService")
    assert sp["status"] == "ok" and sp["hops"] >= 1
    stats = get_graph_stats(cg)
    assert stats["total_nodes"] == len(cg.nodes)

    # Reload from disk cleanly
    reloaded = load_code_graph(polyglot_repo)
    assert reloaded is not None and reloaded.graph_evidence_id == cg.graph_evidence_id


def test_repo_map_and_shortcut_debt(polyglot_repo: Path) -> None:
    rmap = build_repo_map(polyglot_repo, max_chars=2000)
    assert rmap["status"] == "ok"
    assert rmap["char_count"] <= 2000
    assert "src/core" in rmap["map_text"]
    assert "verify_token" in rmap["map_text"]

    debt = scan_shortcut_debt(polyglot_repo)
    assert debt.total_shortcuts == 2
    assert debt.missing_trigger_count == 1
    by_sym = {item.enclosing_symbol: item for item in debt.items}
    assert by_sym["verify_token"].has_upgrade_trigger is True
    assert by_sym["dispatch_action"].has_upgrade_trigger is False


def test_transactional_agent_installer_and_session_hooks(tmp_path: Path) -> None:
    workspace = tmp_path / "agent_ws"
    workspace.mkdir()

    for agent in SUPPORTED_AGENTS:
        dry = install_agent_integration(workspace, agent, dry_run=True)
        assert dry["status"] == "ok" and dry["dry_run"] is True and len(dry["plan"]) >= 1

        res = install_agent_integration(workspace, agent, dry_run=False)
        assert res["status"] == "ok" and len(res["written"]) >= 1
        for p in res["written"]:
            assert Path(p).is_file()

    # Overwrite creates SHA-256 backup
    res2 = install_agent_integration(workspace, "hermes", dry_run=False)
    assert len(res2["backups"]) >= 1
    assert all(Path(b).is_file() for b in res2["backups"])

    # Verify claude-code hook handles UTF-8 stdin and isolates session_id state
    import os
    hook_path = workspace / ".claude" / "hooks" / "athena_hook.py"
    hook_env = {**os.environ, "TEMP": str(tmp_path), "TMPDIR": str(tmp_path)}
    p1 = subprocess.run(
        [sys.executable, str(hook_path), "PreToolUse"],
        input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Grep", "session_id": "sess-alpha-utf8-✓"}).encode("utf-8"),
        env=hook_env,
        capture_output=True,
        check=False,
    )
    assert p1.returncode == 0
    assert "query_code_graph" in p1.stdout.decode("utf-8")

    # Different session_id still gets its own first-time nudge (no cross-session race!)
    p2 = subprocess.run(
        [sys.executable, str(hook_path), "PreToolUse"],
        input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Grep", "session_id": "sess-beta"}).encode("utf-8"),
        env=hook_env,
        capture_output=True,
        check=False,
    )
    assert p2.returncode == 0
    assert "query_code_graph" in p2.stdout.decode("utf-8")


def test_mcp_v13_tools_and_cli_commands(polyglot_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    def _extract(res: Any) -> dict[str, Any]:
        if isinstance(res, dict):
            return res
        if hasattr(res, "structuredContent") and isinstance(res.structuredContent, dict):
            return res.structuredContent
        if hasattr(res, "content") and res.content:
            return json.loads(res.content[0].text)
        if isinstance(res, tuple) and res[0]:
            return json.loads(res[0][0].text)
        raise AssertionError(f"Unexpected MCP result: {res!r}")

    async def _run() -> None:
        tools = await mcp_app.list_tools()
        names = {t.name for t in tools}
        assert {
            "query_code_graph",
            "get_repo_map",
            "scan_debt",
            "inspect_analysis_view",
            "discover_tools",
        }.issubset(names)

        r_disc = _extract(await mcp_app.call_tool("discover_tools", {"query": "graph"}))
        assert r_disc["status"] == "ok" and any(m["name"] == "query_code_graph" for m in r_disc["matches"])

        r_map = _extract(await mcp_app.call_tool("get_repo_map", {"repo_path": str(polyglot_repo)}))
        assert r_map["status"] == "ok" and r_map["char_count"] <= 2000

        r_debt = _extract(await mcp_app.call_tool("scan_debt", {"repo_path": str(polyglot_repo)}))
        assert r_debt["status"] == "ok" and r_debt["total_shortcuts"] == 2

        r_sum = _extract(
            await mcp_app.call_tool(
                "query_code_graph",
                {"repo_path": str(polyglot_repo), "query": "verify_token", "detail": "summary"},
            )
        )
        ev_id = r_sum["parent_evidence_id"]
        r_view = _extract(
            await mcp_app.call_tool(
                "inspect_analysis_view",
                {"evidence_id": ev_id, "facet": "subgraph_nodes", "offset": 0, "limit": 2},
            )
        )
        assert r_view["status"] == "ok" and len(r_view["items"]) <= 2

    asyncio.run(_run())

    assert cli_main(["map", str(polyglot_repo)]) == 0
    captured = capsys.readouterr().out
    assert "src/core" in captured
    assert cli_main(["debt", str(polyglot_repo)]) == 0
    assert cli_main(["graph", str(polyglot_repo), "--god-nodes"]) == 0
    assert cli_main(["install", "--agent", "openclaw", "--target", str(polyglot_repo), "--dry-run"]) == 0
