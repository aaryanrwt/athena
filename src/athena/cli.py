"""Athena CLI & MCP Server Entrypoint."""

from __future__ import annotations

import argparse
import json
import sys

from athena import __version__
from athena.mcp_server import (
    analyze_git_history,
    detect_potential_breaking_changes,
    generate_release_notes,
    inspect_repository,
    run_mcp_stdio_server,
)


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
    sub = parser.add_subparsers(dest="command")

    # mcp server command (default if no subcommand or 'mcp')
    sub.add_parser("mcp", help="Run the Athena MCP server over stdio")

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

    args = parser.parse_args(argv)

    def _resolve_use_llm(cmd_args: argparse.Namespace) -> bool:
        if getattr(cmd_args, "llm", False):
            return True
        if getattr(cmd_args, "no_llm", False):
            return False
        return DEFAULT_ENABLE_LLM

    if args.command in (None, "mcp"):
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

    return 0


if __name__ == "__main__":
    sys.exit(main())

