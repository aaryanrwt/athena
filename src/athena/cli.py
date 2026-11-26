"""Athena CLI & MCP Server Entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from importlib import metadata as importlib_metadata
from pathlib import Path

from athena import __version__
from athena.evidence_store import DEFAULT_EVIDENCE_STORE
from athena.gates import check_staged, semver_check
from athena.html_report import render_html_report
from athena.mcp_server import (
    VALID_TOOLSETS,
    VALID_TRANSPORTS,
    analyze_git_history,
    detect_potential_breaking_changes,
    generate_release_notes,
    get_rust_acceleration_status,
    inspect_repository,
    mcp_app,
    run_mcp_server,
    run_mcp_stdio_server,
)
from athena.mcp_config import render_mcp_config, write_mcp_config
from athena.remediation import generate_fix_plan
from athena.sarif import breaking_report_to_sarif
from athena.security import (
    AthenaValidationError,
    validate_repo_path,
    validate_safe_output_path,
    write_text_safely,
)
from athena.symbol_cache import configure_cache
from athena.token_ledger import get_ledger_status, read_gain_report, reset_gain_ledger
from athena.treesitter_parser import get_treesitter_status
from athena.tui import run_interactive_ui


def _print_error(code: str, message: str, *, exit_code: int = 2) -> int:
    print(json.dumps({"status": "error", "error_code": code, "error_message": message}, indent=2))
    return exit_code


def _run_doctor(repo_path: str, cache_dir: str | None) -> dict[str, object]:
    """Collect real runtime diagnostics for Python, Git, MCP SDK, Rust kernels, and repo state."""
    git_version = ""
    git_ok = False
    try:
        proc = subprocess.run(["git", "--version"], capture_output=True, text=True, check=False, timeout=5)
        if proc.returncode == 0:
            git_ok = True
            git_version = proc.stdout.strip()
    except OSError:
        git_ok = False

    try:
        mcp_sdk_version = importlib_metadata.version("mcp")
    except importlib_metadata.PackageNotFoundError:
        mcp_sdk_version = "missing"

    rust_status = get_rust_acceleration_status()
    ts_status = get_treesitter_status()
    ledger_status = get_ledger_status()
    ev_dir = DEFAULT_EVIDENCE_STORE._storage_dir()
    ev_dir_writable = False
    if ev_dir is not None:
        try:
            ev_dir.mkdir(parents=True, exist_ok=True)
            ev_dir_writable = os.access(ev_dir, os.W_OK)
        except OSError:
            ev_dir_writable = False

    repo_diag = inspect_repository(repo_path=repo_path, max_recent_commits=1)
    graph_file_exists = False
    if repo_diag.get("is_valid_git_repo") and repo_diag.get("repo_root"):
        graph_file_exists = (Path(str(repo_diag["repo_root"])) / ".athena" / "graph.json").is_file()

    runtime_ok = sys.version_info >= (3, 13) and git_ok and mcp_sdk_version != "missing"
    return {
        "status": "ok" if runtime_ok else "error",
        "athena_version": __version__,
        "python": {
            "version": platform.python_version(),
            "executable": sys.executable,
            "supported": sys.version_info >= (3, 13),
        },
        "git": {
            "available": git_ok,
            "version": git_version or "unavailable",
        },
        "mcp": {
            "sdk_version": mcp_sdk_version,
            "registered_tools": len(getattr(mcp_app, "_athena_registered_tools", ())),
            "valid_toolsets": list(VALID_TOOLSETS),
            "transports": list(VALID_TRANSPORTS),
        },
        "rust_acceleration": rust_status,
        "treesitter": ts_status,
        "token_ledger": ledger_status,
        "evidence_store": {
            "directory": str(ev_dir) if ev_dir is not None else None,
            "writable": ev_dir_writable,
            "retained_count": len(DEFAULT_EVIDENCE_STORE.list_retained()),
        },
        "symbol_cache": {
            "cache_dir": cache_dir,
            "enabled": bool(cache_dir),
        },
        "repository": {
            "input_path": repo_path,
            "is_valid_git_repo": bool(repo_diag.get("is_valid_git_repo")),
            "branch": repo_diag.get("current_branch"),
            "graph_index_present": graph_file_exists,
        },
    }


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass

    parser = argparse.ArgumentParser(
        prog="athena",
        description=f"Athena v{__version__}: Local-First Multi-Language Git & AST Release-Readiness and Change-Intelligence Engine",
    )
    parser.add_argument("--version", action="version", version=f"athena {__version__}")
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Opt-in directory for the incremental parsed-symbol cache (or set ATHENA_CACHE_DIR)",
    )
    sub = parser.add_subparsers(dest="command")

    # mcp server command (default if no subcommand or 'mcp')
    p_mcp = sub.add_parser("mcp", help="Run the Athena MCP server (stdio or local streamable-http)")
    p_mcp.add_argument(
        "--transport",
        choices=list(VALID_TRANSPORTS),
        default="stdio",
        help="MCP transport mode: stdio (default) or streamable-http",
    )
    p_mcp.add_argument("--host", default="127.0.0.1", help="Bind host for streamable-http (default: 127.0.0.1)")
    p_mcp.add_argument("--port", type=int, default=8765, help="Bind port for streamable-http (default: 8765)")
    p_mcp.add_argument(
        "--toolsets",
        default=None,
        help=f"Comma-separated MCP toolsets to expose ({', '.join(VALID_TOOLSETS)}, or all)",
    )
    p_mcp.add_argument(
        "--read-only",
        action="store_true",
        help="Expose only read-only MCP tools (excludes file-writing release note tools)",
    )
    p_mcp.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow non-loopback streamable-http binding (use with caution)",
    )

    # interactive terminal UI command
    p_ui = sub.add_parser("ui", help="Launch the interactive Athena Studio Terminal UI")
    p_ui.add_argument("repo_path", nargs="?", default=".", help="Path to local Git repository (default: .)")

    # inspect command
    p_inspect = sub.add_parser("inspect", help="Inspect a local Git repository (read-only)")
    p_inspect.add_argument("repo_path", help="Path to local Git repository")
    p_inspect.add_argument("--max-commits", type=int, default=10, help="Maximum recent commits to return")

    from athena.ollama_engine import DEFAULT_ENABLE_LLM, DEFAULT_OLLAMA_MODEL

    # analyze command
    p_analyze = sub.add_parser("analyze", help="Analyze Git history and code diffs between two revisions")
    p_analyze.add_argument("repo_path", help="Path to local Git repository")
    p_analyze.add_argument("--base", default="AUTO", help="Base revision (tag, branch, SHA, or AUTO)")
    p_analyze.add_argument("--target", default="HEAD", help="Target revision (HEAD, tag, branch, or WORKING_TREE)")
    p_analyze.add_argument("--max-commits", type=int, default=100, help="Maximum commits to inspect (1..500)")
    p_analyze.add_argument("--detail", choices=["complete", "summary"], default="complete", help="Response detail level (summary retains ev_<sha256> on disk for athena view)")
    p_analyze.add_argument("--llm", action="store_true", help="Enable optional local LLM (qwen2.5-coder:7b / gemma:latest) enhancement")
    p_analyze.add_argument("--no-llm", action="store_true", help="Force deterministic AST/diff mode (default)")
    p_analyze.add_argument("--model", default=DEFAULT_OLLAMA_MODEL, help="Local Ollama model tag (e.g. qwen2.5-coder:7b, gemma:latest)")

    # breaking-changes command
    p_brk = sub.add_parser("breaking-changes", help="Detect potential breaking changes requiring human review")
    p_brk.add_argument("repo_path", help="Path to local Git repository")
    p_brk.add_argument("--base", default="AUTO", help="Base revision (tag, branch, SHA, or AUTO)")
    p_brk.add_argument("--target", default="HEAD", help="Target revision (HEAD, tag, branch, or WORKING_TREE)")
    p_brk.add_argument("--include-low-confidence", action="store_true", help="Include low-confidence findings")
    p_brk.add_argument("--detail", choices=["complete", "summary"], default="complete", help="Response detail level (summary retains ev_<sha256> on disk for athena view)")
    p_brk.add_argument("--llm", action="store_true", help="Enable optional local LLM (qwen2.5-coder:7b / gemma:latest) enhancement")
    p_brk.add_argument("--no-llm", action="store_true", help="Force deterministic AST/diff mode (default)")
    p_brk.add_argument("--model", default=DEFAULT_OLLAMA_MODEL, help="Local Ollama model tag (e.g. qwen2.5-coder:7b, gemma:latest)")

    # release-notes command
    p_rel = sub.add_parser("release-notes", help="Generate structured, evidence-backed release notes")
    p_rel.add_argument("repo_path", help="Path to local Git repository")
    p_rel.add_argument("--base", default="AUTO", help="Base revision (tag, branch, SHA, or AUTO)")
    p_rel.add_argument("--target", default="HEAD", help="Target revision (HEAD, tag, branch, or WORKING_TREE)")
    p_rel.add_argument("--version", default="Unreleased", help="Release version label")
    p_rel.add_argument(
        "--audience",
        default="developers",
        choices=["end_users", "developers", "maintainers", "clients"],
        help="Target audience for release notes",
    )
    p_rel.add_argument("--output", default=None, help="Optional relative file path to save Markdown release notes")
    p_rel.add_argument("--overwrite", action="store_true", help="Allow overwriting existing output file")
    p_rel.add_argument("--markdown-only", action="store_true", help="Print only rendered Markdown instead of JSON")
    p_rel.add_argument("--llm", action="store_true", help="Enable optional local LLM (qwen2.5-coder:7b / gemma:latest) enhancement")
    p_rel.add_argument("--no-llm", action="store_true", help="Force deterministic AST/diff mode (default)")
    p_rel.add_argument("--model", default=DEFAULT_OLLAMA_MODEL, help="Local Ollama model tag (e.g. qwen2.5-coder:7b, gemma:latest)")

    p_brk.add_argument(
        "--format",
        choices=["json", "sarif"],
        default="json",
        help="Output format: json (default) or sarif (SARIF 2.1.0 for code scanning)",
    )

    # init-mcp command
    p_init = sub.add_parser("init-mcp", help="Print or write ready MCP client configuration JSON")
    p_init.add_argument("client", choices=["claude-desktop", "cursor", "vscode"], help="Target MCP client")
    p_init.add_argument("--write", action="store_true", help="Write the config to --path instead of printing it")
    p_init.add_argument("--path", default=None, help="Explicit target file path (required with --write)")
    p_init.add_argument("--force", action="store_true", help="Allow overwriting an existing --path file")

    # check command (pre-commit)
    p_chk = sub.add_parser("check", help="Deterministic breaking-change gate for pre-commit")
    p_chk.add_argument("repo_path", nargs="?", default=".", help="Path to local Git repository (default: .)")
    p_chk.add_argument("--staged", action="store_true", help="Analyze staged (index) changes against HEAD")
    p_chk.add_argument(
        "--allow-breaking",
        action="store_true",
        help="Audit-only mode: print breaking changes but exit 0 (override for intentional breaking changes)",
    )

    # report command
    p_rep = sub.add_parser("report", help="Render a static breaking-change report")
    p_rep.add_argument("repo_path", help="Path to local Git repository")
    p_rep.add_argument("--html", action="store_true", help="Render a single-file static HTML report")
    p_rep.add_argument("--base", default="AUTO", help="Base revision (tag, branch, SHA, or AUTO)")
    p_rep.add_argument("--target", default="HEAD", help="Target revision (HEAD, tag, branch, or WORKING_TREE)")
    p_rep.add_argument("--include-low-confidence", action="store_true", help="Include low-confidence findings")
    p_rep.add_argument("--output", default=None, help="Relative file path inside the repository to write (default: stdout)")
    p_rep.add_argument("--overwrite", action="store_true", help="Allow overwriting an existing output file")

    # semver-check command
    p_sem = sub.add_parser("semver-check", help="Fail when the declared version bump is smaller than required")
    p_sem.add_argument("repo_path", help="Path to local Git repository")
    p_sem.add_argument("--base", default="AUTO", help="Base revision (tag, branch, SHA, or AUTO)")
    p_sem.add_argument("--target", default="HEAD", help="Target revision (HEAD, tag, branch, or WORKING_TREE)")
    p_sem.add_argument("--declared", required=True, choices=["major", "minor", "patch"], help="Declared bump")

    # graph command
    p_graph = sub.add_parser("graph", help="Build or query Athena's persistent code knowledge graph")
    p_graph.add_argument("repo_path", nargs="?", default=".", help="Path to local repository (default: .)")
    p_graph.add_argument("--query", default="", help="Search query for trigram+IDF + hub-guarded BFS")
    p_graph.add_argument("--depth", type=int, default=2, help="BFS depth (default: 2)")
    p_graph.add_argument("--token-budget", type=int, default=2000, help="Token budget (default: 2000)")
    p_graph.add_argument("--god-nodes", action="store_true", help="List top architectural hub nodes")
    p_graph.add_argument("--path", nargs=2, metavar=("SRC", "DST"), help="Find shortest path between two symbols")
    p_graph.add_argument("--rebuild", action="store_true", help="Force graph rebuild")
    p_graph.add_argument("--detail", choices=["complete", "summary"], default="complete", help="Response detail level (summary retains ev_<sha256> on disk for athena view)")

    # map command
    p_map = sub.add_parser("map", help="Emit a <=2000-char zero-search architectural export map")
    p_map.add_argument("repo_path", nargs="?", default=".", help="Path to local repository (default: .)")
    p_map.add_argument("--max-chars", type=int, default=2000, help="Maximum output characters (default: 2000)")
    p_map.add_argument("--json", action="store_true", help="Output full JSON metadata")

    # debt command
    p_debt = sub.add_parser("debt", help="Scan for `shortcut:` technical debt markers bound to AST symbols")
    p_debt.add_argument("repo_path", nargs="?", default=".", help="Path to local repository (default: .)")
    p_debt.add_argument("--include-todos", action="store_true", help="Also include TODO/FIXME markers")
    p_debt.add_argument("--offset", type=int, default=0, help="Start item offset (default: 0)")
    p_debt.add_argument("--limit", type=int, default=None, help="Maximum items to return (1..500)")

    # install command
    p_inst = sub.add_parser("install", help="Transactionally install Athena skills/hooks for AI coding agents")
    p_inst.add_argument(
        "--agent",
        required=True,
        choices=["hermes", "openclaw", "claude-code", "codex", "cursor", "pi"],
        help="Target AI agent platform",
    )
    p_inst.add_argument("--target", default=".", help="Target project/workspace directory (default: .)")
    p_inst.add_argument("--dry-run", action="store_true", help="Preview installation plan without writing files")

    # view command
    p_view = sub.add_parser("view", help="Page through a retained evidence bundle by ID and facet")
    p_view.add_argument("evidence_id", help="Retained evidence ID (ev_<sha256>)")
    p_view.add_argument("--facet", required=True, help="Facet name to inspect")
    p_view.add_argument("--offset", type=int, default=0, help="Start offset")
    p_view.add_argument("--limit", type=int, default=50, help="Page size")

    # affected-tests command
    p_tests = sub.add_parser("affected-tests", help="Predict pytest/Playwright/unit tests impacted by git diff")
    p_tests.add_argument("repo_path", nargs="?", default=".", help="Path to local Git repository (default: .)")
    p_tests.add_argument("--base", default="AUTO", help="Base revision (tag, branch, SHA, or AUTO)")
    p_tests.add_argument("--target", default="HEAD", help="Target revision (HEAD, tag, branch, or WORKING_TREE)")
    p_tests.add_argument("--offset", type=int, default=0, help="Start item offset (default: 0)")
    p_tests.add_argument("--limit", type=int, default=None, help="Maximum tests to return (1..500)")

    # doctor command (v1.3.2+)
    p_doc = sub.add_parser("doctor", help="Check Python, Git, MCP SDK, Rust kernel, Tree-sitter, cache, and repo readiness")
    p_doc.add_argument("repo_path", nargs="?", default=".", help="Optional local repository path to inspect (default: .)")

    # fix command (v1.3.3)
    p_fix = sub.add_parser("fix", help="Generate deterministic remediation patches and unified diffs (dry-run default)")
    p_fix.add_argument("repo_path", nargs="?", default=".", help="Path to local Git repository (default: .)")
    p_fix.add_argument("--base", default="AUTO", help="Base revision (tag, branch, SHA, or AUTO)")
    p_fix.add_argument("--target", default="HEAD", help="Target revision (HEAD, tag, branch, or WORKING_TREE)")
    p_fix.add_argument("--apply", action="store_true", help="Apply non-overlapping safe patches atomically on disk")
    p_fix.add_argument("--include-review-required", action="store_true", help="Also apply review_required patches when --apply is set")
    p_fix.add_argument("--include-low-confidence", action="store_true", help="Include low-confidence findings")
    p_fix.add_argument("--format", choices=["json", "diff"], default="json", help="Output format: json (default) or diff")

    # gain command (v1.3.3)
    p_gain = sub.add_parser("gain", help="Show measured raw vs compacted context/token savings across Athena runs")
    p_gain.add_argument("repo_path", nargs="?", default=".", help="Optional local repository path filter (default: .)")
    p_gain.add_argument("--all", action="store_true", help="Aggregate across all recorded repositories")
    p_gain.add_argument("--limit", type=int, default=20, help="Recent entries to return (default: 20)")
    p_gain.add_argument("--reset", action="store_true", help="Reset the local token-savings ledger file")

    args = parser.parse_args(argv)

    cache_dir = args.cache_dir or os.environ.get("ATHENA_CACHE_DIR") or None
    try:
        configure_cache(cache_dir)
    except AthenaValidationError as exc:
        print(json.dumps({"status": "error", "error_code": exc.code, "error_message": exc.message}, indent=2))
        return 2

    def _resolve_use_llm(cmd_args: argparse.Namespace) -> bool:
        if getattr(cmd_args, "llm", False):
            return True
        if getattr(cmd_args, "no_llm", False):
            return False
        return DEFAULT_ENABLE_LLM

    if args.command == "ui":
        return run_interactive_ui(args.repo_path)

    if args.command is None:
        if sys.stdin.isatty():
            return run_interactive_ui(".")
        run_mcp_stdio_server()
        return 0

    if args.command == "mcp":
        try:
            run_mcp_server(
                transport=args.transport,
                host=args.host,
                port=args.port,
                toolsets=args.toolsets,
                read_only=args.read_only,
                allow_remote=args.allow_remote,
            )
            return 0
        except AthenaValidationError as exc:
            return _print_error(exc.code, exc.message, exit_code=2)

    if args.command == "inspect":
        res = inspect_repository(repo_path=args.repo_path, max_recent_commits=args.max_commits)
        print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    if args.command == "analyze":
        res = analyze_git_history(
            repo_path=args.repo_path,
            base_ref=args.base,
            target_ref=args.target,
            max_commits=args.max_commits,
            use_llm=_resolve_use_llm(args),
            ollama_model=args.model,
            detail=args.detail,
        )
        print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    if args.command == "breaking-changes":
        if args.format == "sarif" and args.detail == "summary":
            return _print_error(
                "INCOMPATIBLE_OPTIONS",
                "--format sarif requires complete findings; omit --detail summary when exporting SARIF.",
                exit_code=2,
            )
        res = detect_potential_breaking_changes(
            repo_path=args.repo_path,
            base_ref=args.base,
            target_ref=args.target,
            include_low_confidence=args.include_low_confidence,
            use_llm=_resolve_use_llm(args),
            ollama_model=args.model,
            detail=args.detail,
        )
        if args.format == "sarif" and res.get("status") == "ok":
            print(json.dumps(breaking_report_to_sarif(res), indent=2))
        else:
            print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    if args.command == "release-notes":
        res = generate_release_notes(
            repo_path=args.repo_path,
            base_ref=args.base,
            target_ref=args.target,
            release_version=args.version,
            audience=args.audience,
            output_file=args.output,
            overwrite=args.overwrite,
            use_llm=_resolve_use_llm(args),
            ollama_model=args.model,
        )
        if args.markdown_only and res.get("status") == "ok":
            print(res.get("markdown", ""))
        else:
            print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    if args.command == "init-mcp":
        try:
            if args.write:
                if not args.path:
                    print(json.dumps({"status": "error", "error_code": "PATH_REQUIRED",
                                      "error_message": "--write requires an explicit --path <file>."}, indent=2))
                    return 2
                written = write_mcp_config(args.client, args.path, force=args.force)
                print(json.dumps({"status": "ok", "client": args.client, "written_to": str(written)}, indent=2))
            else:
                print(render_mcp_config(args.client), end="")
            return 0
        except AthenaValidationError as exc:
            print(json.dumps({"status": "error", "error_code": exc.code, "error_message": exc.message}, indent=2))
            return 1

    if args.command == "check":
        if not args.staged:
            print(json.dumps({"status": "error", "error_code": "MODE_REQUIRED",
                              "error_message": "Specify --staged to analyze staged changes."}, indent=2))
            return 2
        res = check_staged(args.repo_path)
        if res.get("status") != "ok":
            print(json.dumps(res, indent=2))
            return 2
        findings = res.get("potential_breaking_changes") or []
        for f in findings:
            print(f"athena: potential breaking change [{f.get('severity')}] {f.get('file_path')}: {f.get('title')}")
        if findings:
            print(f"athena: {len(findings)} potential breaking change(s) in staged changes; review before committing.")
            return 0 if args.allow_breaking else 1
        return 0

    if args.command == "report":
        if not args.html:
            print(json.dumps({"status": "error", "error_code": "FORMAT_REQUIRED",
                              "error_message": "Specify --html to render the static report."}, indent=2))
            return 2
        res = detect_potential_breaking_changes(
            repo_path=args.repo_path,
            base_ref=args.base,
            target_ref=args.target,
            include_low_confidence=args.include_low_confidence,
            use_llm=False,
        )
        html_text = render_html_report(res)
        if args.output:
            try:
                root = validate_repo_path(args.repo_path)
                target = validate_safe_output_path(root, args.output, overwrite=args.overwrite)
                write_text_safely(target, html_text, overwrite=args.overwrite)
            except AthenaValidationError as exc:
                print(json.dumps({"status": "error", "error_code": exc.code, "error_message": exc.message}, indent=2))
                return 1
            print(json.dumps({"status": res.get("status"), "saved_to_file": str(target)}, indent=2))
        else:
            print(html_text, end="")
        return 0 if res.get("status") == "ok" else 1

    if args.command == "semver-check":
        try:
            res = semver_check(args.repo_path, args.base, args.target, args.declared)
        except AthenaValidationError as exc:
            res = {"status": "error", "error_code": exc.code, "error_message": exc.message}
        print(json.dumps(res, indent=2))
        if res.get("status") != "ok":
            return 2
        return 0 if res.get("gate_passed") else 1

    if args.command == "graph":
        from athena.graph_query import get_god_nodes, get_graph_stats, query_code_graph, shortest_path_between
        from athena.graph_store import DEFAULT_GRAPH_MANAGER

        try:
            cg = DEFAULT_GRAPH_MANAGER.get_or_build(args.repo_path, rebuild=args.rebuild)
            if args.path:
                out = shortest_path_between(cg, args.path[0], args.path[1])
            elif args.god_nodes:
                out = {"status": "ok", "god_nodes": get_god_nodes(cg)}
            elif args.query:
                out = query_code_graph(cg, args.query, depth=args.depth, token_budget=args.token_budget)
            else:
                out = get_graph_stats(cg)
            if args.detail == "summary" and out.get("status") == "ok":
                out = DEFAULT_EVIDENCE_STORE.retain(
                    "code_graph_query",
                    out,
                    completeness=cg.completeness,
                )
            print(json.dumps(out, indent=2))
            return 0 if out.get("status") == "ok" else 1
        except AthenaValidationError as exc:
            return _print_error(exc.code, exc.message, exit_code=2)

    if args.command == "map":
        from athena.repo_map import build_repo_map

        try:
            res = build_repo_map(args.repo_path, max_chars=args.max_chars)
            if res.get("status") != "ok":
                print(json.dumps(res, indent=2))
                return 1
            if args.json:
                print(json.dumps(res, indent=2))
            else:
                print(res["map_text"])
            return 0
        except AthenaValidationError as exc:
            return _print_error(exc.code, exc.message, exit_code=2)

    if args.command == "debt":
        from athena.debt_tracker import scan_shortcut_debt

        try:
            res = scan_shortcut_debt(
                args.repo_path,
                include_todos=args.include_todos,
                offset=args.offset,
                limit=args.limit,
            ).model_dump(mode="json")
            print(json.dumps(res, indent=2))
            return 0 if res.get("status") == "ok" else 1
        except AthenaValidationError as exc:
            return _print_error(exc.code, exc.message, exit_code=2)

    if args.command == "install":
        from athena.agent_installer import install_agent_integration

        res = install_agent_integration(args.target, args.agent, dry_run=args.dry_run)
        print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    if args.command == "view":
        res = DEFAULT_EVIDENCE_STORE.inspect_view(args.evidence_id, args.facet, offset=args.offset, limit=args.limit)
        print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    if args.command == "affected-tests":
        from athena.test_selector import predict_affected_tests

        try:
            res = predict_affected_tests(
                args.repo_path,
                base_ref=args.base,
                target_ref=args.target,
                offset=args.offset,
                limit=args.limit,
            )
            print(json.dumps(res, indent=2))
            return 0 if res.get("status") == "ok" else 1
        except AthenaValidationError as exc:
            return _print_error(exc.code, exc.message, exit_code=2)

    if args.command == "doctor":
        diag = _run_doctor(args.repo_path, cache_dir)
        print(json.dumps(diag, indent=2))
        return 0 if diag.get("status") == "ok" else 1

    if args.command == "fix":
        res = generate_fix_plan(
            repo_path=args.repo_path,
            base_ref=args.base,
            target_ref=args.target,
            apply=args.apply,
            include_review_required=args.include_review_required,
            include_low_confidence=args.include_low_confidence,
        ).model_dump(mode="json")
        if args.format == "diff" and res.get("status") == "ok":
            diffs = [p["unified_diff"] for p in res.get("patches", []) if p.get("unified_diff")]
            print("\n".join(diffs) if diffs else "# No concrete line edits generated (see --format json for migration guides).")
        else:
            print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    if args.command == "gain":
        if args.reset:
            out = reset_gain_ledger()
            print(json.dumps(out, indent=2))
            return 0 if out.get("status") == "ok" else 1
        if isinstance(args.limit, bool) or args.limit < 1 or args.limit > 200:
            return _print_error("INVALID_LIMIT", "limit must be an integer between 1 and 200.", exit_code=2)
        scope = None if args.all else args.repo_path
        res = read_gain_report(scope, limit=args.limit)
        print(json.dumps(res, indent=2))
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())

