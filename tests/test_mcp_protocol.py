"""MCP Protocol Integration Tests: Verifies Athena MCP Server over MCPServer API and Real Stdio JSON-RPC Transport."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from athena.mcp_server import mcp_app


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


@pytest.fixture()
def mcp_test_repo(tmp_path: Path) -> Path:
    """Create a multi-commit Git repository including qwen2.5-coder:7b's suggested unguarded default=None test case."""
    repo = tmp_path / "mcp_repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "MCP Tester")
    _git(repo, "config", "user.email", "mcp@example.com")

    (repo / "math_ops.py").write_text(
        "def example_function(param: int = 10) -> int:\n"
        "    return param * 2\n\n"
        "def safe_function(param: int = 10) -> int:\n"
        "    return param + 1\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat: initial math_ops")
    _git(repo, "tag", "v1.0.0")

    # Apply qwen2.5-coder:7b's suggested test case:
    # - example_function changes default=10 to default=None WITHOUT a body guard -> breaking!
    # - safe_function changes default=10 to default=None WITH `if param is None:` guard -> non-breaking!
    (repo / "math_ops.py").write_text(
        "def example_function(param: int | None = None) -> int:\n"
        "    return param * 2\n\n"
        "def safe_function(param: int | None = None) -> int:\n"
        "    if param is None:\n"
        "        param = 10\n"
        "    return param + 1\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "refactor: update default parameters to None")
    _git(repo, "tag", "v1.1.0")
    return repo


def _extract_json_from_call_tool_result(result: Any) -> dict[str, Any]:
    """Extract parsed JSON dictionary from MCP CallToolResult across MCP SDK 1.x / 2.x."""
    if isinstance(result, dict):
        return result
    if isinstance(result, tuple):
        for part in reversed(result):
            if isinstance(part, dict):
                return part
        if result and isinstance(result[0], list):
            result = type("_R", (), {"content": result[0]})()
    if hasattr(result, "structuredContent") and isinstance(result.structuredContent, dict):
        return result.structuredContent
    if hasattr(result, "content") and result.content:
        first = result.content[0]
        if hasattr(first, "text"):
            return json.loads(first.text)
    raise AssertionError(f"Could not extract JSON payload from CallToolResult: {result!r}")


def test_mcp_server_tool_registration_and_unguarded_none_default(mcp_test_repo: Path) -> None:
    """Verify MCP tool schemas and qwen2.5-coder:7b's suggested unguarded vs guarded default=None AST rule."""

    async def _run() -> None:
        tools = await mcp_app.list_tools()
        tool_names = {t.name for t in tools}
        assert {
            "inspect_repository",
            "analyze_git_history",
            "generate_release_notes",
            "detect_potential_breaking_changes",
            "analyze_change_graph",
            "verify_breaking_and_doc_drift",
            "generate_verified_release_brief",
        }.issubset(tool_names)

        # Analysis tools are read-only. Release tools can create/replace an explicit output_file,
        # so their MCP hints must disclose mutation and potential overwrite behavior.
        for t in tools:
            assert t.annotations is not None, f"Tool {t.name} missing annotations"
            dumped_ann = t.annotations.model_dump(by_alias=True)
            if t.name in {"generate_release_notes", "generate_verified_release_brief"}:
                assert dumped_ann["readOnlyHint"] is False
                assert dumped_ann["destructiveHint"] is True
                assert dumped_ann["idempotentHint"] is False
            else:
                assert dumped_ann["readOnlyHint"] is True, f"Tool {t.name} missing readOnlyHint=True"
                assert dumped_ann["destructiveHint"] is False, f"Tool {t.name} missing destructiveHint=False"
                assert dumped_ann["idempotentHint"] is True, f"Tool {t.name} missing idempotentHint=True"
            if t.name == "inspect_repository":
                assert dumped_ann["openWorldHint"] is False
            else:
                # Every analysis/release tool can optionally contact the configured
                # Ollama endpoint when its LLM flag is explicitly enabled.
                assert dumped_ann["openWorldHint"] is True

        res_brk = await mcp_app.call_tool(
            "detect_potential_breaking_changes",
            {
                "repo_path": str(mcp_test_repo),
                "base_ref": "v1.0.0",
                "target_ref": "v1.1.0",
                "use_llm": False,
            },
        )
        payload = _extract_json_from_call_tool_result(res_brk)
        assert payload["status"] == "ok"
        flagged_symbols = {f["affected_symbol"] for f in payload["potential_breaking_changes"]}
        # Unguarded default=None (qwen2.5-coder:7b test case) MUST be flagged!
        assert "example_function" in flagged_symbols
        # Guarded default=None (griffe#469 fix) MUST NOT be flagged!
        assert "safe_function" not in flagged_symbols

        # Also test the spec alias verify_breaking_and_doc_drift
        res_alias = await mcp_app.call_tool(
            "verify_breaking_and_doc_drift",
            {
                "repo_path": str(mcp_test_repo),
                "base_ref": "v1.0.0",
                "head_ref": "v1.1.0",
                "enable_llm_behavioral_pass": False,
            },
        )
        payload_alias = _extract_json_from_call_tool_result(res_alias)
        assert payload_alias["status"] == "ok"
        flagged_alias = {f["affected_symbol"] for f in payload_alias["potential_breaking_changes"]}
        assert "example_function" in flagged_alias
        assert "safe_function" not in flagged_alias

    asyncio.run(_run())


@pytest.mark.timeout(120)
def test_real_mcp_stdio_client_server_roundtrip(mcp_test_repo: Path) -> None:
    """Launch Athena MCP server as a real subprocess over stdio and invoke all 4 tools via MCP ClientSession."""

    async def _run_stdio() -> None:
        src_dir = str(Path(__file__).resolve().parent.parent / "src")
        env = dict(os.environ)
        env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "athena.mcp_server"],
            env=env,
        )
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                tools_resp = await session.list_tools()
                names = {t.name for t in tools_resp.tools}
                assert {
                    "inspect_repository",
                    "analyze_git_history",
                    "generate_release_notes",
                    "detect_potential_breaking_changes",
                }.issubset(names)

                # 1. Call inspect_repository over stdio
                r1 = await session.call_tool(
                    "inspect_repository",
                    {"repo_path": str(mcp_test_repo), "max_recent_commits": 5},
                )
                p1 = _extract_json_from_call_tool_result(r1)
                assert p1["status"] == "ok"
                assert p1["is_valid_git_repo"] is True

                # 2. Call analyze_git_history over stdio
                r2 = await session.call_tool(
                    "analyze_git_history",
                    {
                        "repo_path": str(mcp_test_repo),
                        "base_ref": "v1.0.0",
                        "target_ref": "v1.1.0",
                        "use_llm": False,
                    },
                )
                p2 = _extract_json_from_call_tool_result(r2)
                assert p2["status"] == "ok"
                assert p2["total_commits"] == 1

                # 3. Call generate_release_notes over stdio
                r3 = await session.call_tool(
                    "generate_release_notes",
                    {
                        "repo_path": str(mcp_test_repo),
                        "base_ref": "v1.0.0",
                        "target_ref": "v1.1.0",
                        "release_version": "v1.1.0",
                        "audience": "developers",
                        "use_llm": False,
                    },
                )
                p3 = _extract_json_from_call_tool_result(r3)
                assert p3["status"] == "ok"
                assert "# Release Notes — v1.1.0" in p3["markdown"]

                # 4. Call detect_potential_breaking_changes over stdio
                r4 = await session.call_tool(
                    "detect_potential_breaking_changes",
                    {
                        "repo_path": str(mcp_test_repo),
                        "base_ref": "v1.0.0",
                        "target_ref": "v1.1.0",
                        "use_llm": False,
                    },
                )
                p4 = _extract_json_from_call_tool_result(r4)
                assert p4["status"] == "ok"
                assert p4["total_potential_breaking_changes"] == 1

    asyncio.run(_run_stdio())
