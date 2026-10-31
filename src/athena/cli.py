"""Athena CLI & MCP Server Entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import sys

from athena import __version__
from athena.gates import check_staged, semver_check
from athena.html_report import render_html_report
from athena.mcp_server import (
    analyze_git_history,
    detect_potential_breaking_changes,
    generate_release_notes,
    inspect_repository,
    run_mcp_stdio_server,
)
from athena.mcp_config import render_mcp_config, write_mcp_config
from athena.sarif import breaking_report_to_sarif
from athena.security import (
    AthenaValidationError,
    validate_repo_path,
    validate_safe_output_path,
    write_text_safely,
)
from athena.symbol_cache import configure_cache
from athena.tui import run_interactive_ui


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
    sub.add_parser("mcp", help="Run the Athena MCP server over stdio")

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
    p_analyze.add_argument("--llm", action="store_true", help="Enable optional local LLM (qwen2.5-coder:7b / gemma:latest) enhancement")
    p_analyze.add_argument("--no-llm", action="store_true", help="Force deterministic AST/diff mode (default)")
    p_analyze.add_argument("--model", default=DEFAULT_OLLAMA_MODEL, help="Local Ollama model tag (e.g. qwen2.5-coder:7b, gemma:latest)")

    # breaking-changes command
    p_brk = sub.add_parser("breaking-changes", help="Detect potential breaking changes requiring human review")
    p_brk.add_argument("repo_path", help="Path to local Git repository")
    p_brk.add_argument("--base", default="AUTO", help="Base revision (tag, branch, SHA, or AUTO)")
    p_brk.add_argument("--target", default="HEAD", help="Target revision (HEAD, tag, branch, or WORKING_TREE)")
    p_brk.add_argument("--include-low-confidence", action="store_true", help="Include low-confidence findings")
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
        run_mcp_stdio_server()
        return 0

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
        )
        print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    if args.command == "breaking-changes":
        res = detect_potential_breaking_changes(
            repo_path=args.repo_path,
            base_ref=args.base,
            target_ref=args.target,
            include_low_confidence=args.include_low_confidence,
            use_llm=_resolve_use_llm(args),
            ollama_model=args.model,
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

    return 0


if __name__ == "__main__":
    sys.exit(main())

