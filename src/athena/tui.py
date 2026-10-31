"""Athena Interactive Terminal UI (TUI).

Stylized interactive terminal interface featuring retro modular block typography,
warm terracotta color palette, and frictionless developer ergonomics.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

from athena import __version__
from athena.gates import check_staged, semver_check
from athena.html_report import render_html_report
from athena.mcp_config import render_mcp_config, write_mcp_config
from athena.mcp_server import (
    DEFAULT_ENABLE_LLM,
    DEFAULT_OLLAMA_MODEL,
    analyze_git_history,
    detect_potential_breaking_changes,
    inspect_repository,
    run_mcp_stdio_server,
)
from athena.sarif import breaking_report_to_sarif
from athena.security import validate_repo_path, validate_safe_output_path, write_text_safely

# Color Palette (Athena Terracotta / Warm Coral brand aesthetics)
CORAL = "\033[38;2;217;119;87m"
CORAL_BOLD = "\033[1;38;2;217;119;87m"
CORAL_DIM = "\033[38;2;170;90;65m"
CREAM = "\033[38;2;245;235;225m"
CREAM_BOLD = "\033[1;38;2;245;235;225m"
MUTED = "\033[38;2;130;130;130m"
DOT_RED = "\033[38;2;237;106;94m"
DOT_YELLOW = "\033[38;2;245;191;79m"
DOT_GREEN = "\033[38;2;98;197;84m"
GREEN = "\033[38;2;98;197;84m"
YELLOW = "\033[38;2;245;191;79m"
RED = "\033[38;2;237;106;94m"
CYAN = "\033[38;2;86;182;194m"
RESET = "\033[0m"
BOLD = "\033[1m"


def _enable_windows_vt100() -> None:
    """Ensure Windows terminal supports VT100 ANSI sequences."""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


def _get_git_status_summary(repo_path: str = ".") -> dict[str, Any]:
    """Retrieve light Git repository summary for the header card."""
    info: dict[str, Any] = {
        "is_git": False,
        "branch": "unknown",
        "head_sha": "unknown",
        "staged_count": 0,
        "unstaged_count": 0,
        "repo_name": os.path.basename(os.path.abspath(repo_path)),
    }
    try:
        root_res = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        info["is_git"] = True
        info["repo_name"] = os.path.basename(root_res.stdout.strip())

        branch_res = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
        )
        if branch_res.returncode == 0:
            info["branch"] = branch_res.stdout.strip()

        sha_res = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
        )
        if sha_res.returncode == 0:
            info["head_sha"] = sha_res.stdout.strip()

        status_res = subprocess.run(
            ["git", "-C", repo_path, "status", "--porcelain"],
            capture_output=True,
            text=True,
        )
        if status_res.returncode == 0:
            lines = [line for line in status_res.stdout.splitlines() if line.strip()]
            staged = [l for l in lines if l[0] not in (" ", "?")]
            unstaged = [l for l in lines if len(l) > 1 and l[1] != " "]
            info["staged_count"] = len(staged)
            info["unstaged_count"] = len(unstaged)
    except Exception:
        pass
    return info


def print_banner(git_info: dict[str, Any]) -> None:
    """Render Athena retro modular block banner and header."""
    _enable_windows_vt100()

    print()
    print(f"  {DOT_RED}●{RESET} {DOT_YELLOW}●{RESET} {DOT_GREEN}●{RESET}  {MUTED}athena v{__version__} — local-first change intelligence{RESET}")
    print()
    print(f"  {CORAL}╭─────────────────────────────────╮{RESET}")
    print(f"  {CORAL}│{RESET}  {CREAM_BOLD}✱ Welcome to Athena Studio{RESET}     {CORAL}│{RESET}")
    print(f"  {CORAL}╰─────────────────────────────────╯{RESET}")
    print()

    # Modular segmented block typography
    logo_lines = [
        r"  █████  ████████ ██   ██ ███████ ███    ██  █████  ",
        r" ██   ██    ██    ██   ██ ██      ████   ██ ██   ██ ",
        r" ███████    ██    ███████ █████   ██ ██  ██ ███████ ",
        r" ██   ██    ██    ██   ██ ██      ██  ██ ██ ██   ██ ",
        r" ██   ██    ██    ██   ██ ███████ ██   ████ ██   ██ ",
    ]
    for line in logo_lines:
        print(f"  {CORAL_BOLD}{line}{RESET}")

    print()
    print(f'  {CREAM_BOLD}"Your git diff says it is safe. Athena checks the callers."{RESET}')
    print(f"  {MUTED}Deterministic AST Core • 14 Languages • Model Context Protocol • Zero-LLM Default{RESET}")
    print()

    # Workspace status badge
    if git_info.get("is_git"):
        staged_badge = f"{GREEN}{git_info['staged_count']} staged{RESET}" if git_info["staged_count"] else f"{MUTED}0 staged{RESET}"
        unstaged_badge = f"{YELLOW}{git_info['unstaged_count']} unstaged{RESET}" if git_info["unstaged_count"] else f"{MUTED}clean{RESET}"
        print(
            f"  {CORAL}Repository:{RESET} {CREAM_BOLD}{git_info['repo_name']}{RESET}  "
            f"{MUTED}│{RESET}  {CORAL}Branch:{RESET} {CYAN}{git_info['branch']}{RESET} ({git_info['head_sha']})  "
            f"{MUTED}│{RESET}  {staged_badge}  "
            f"{MUTED}│{RESET}  {unstaged_badge}"
        )
    else:
        print(f"  {YELLOW}Notice:{RESET} Current directory is not a Git repository. Specify a repo path for analysis.")
    print()


def print_menu() -> None:
    """Print the interactive action options."""
    print(f"  {CORAL_BOLD}Available Actions:{RESET}")
    print(f"  {CORAL}[1]{RESET}  {CREAM_BOLD}Check Staged Changes{RESET}         {MUTED}Deterministic pre-commit breaking-change gate{RESET}")
    print(f"  {CORAL}[2]{RESET}  {CREAM_BOLD}Detect Breaking Changes{RESET}      {MUTED}Working tree / branch vs baseline with blast radius{RESET}")
    print(f"  {CORAL}[3]{RESET}  {CREAM_BOLD}Generate HTML Report{RESET}         {MUTED}Standalone single-file interactive audit report{RESET}")
    print(f"  {CORAL}[4]{RESET}  {CREAM_BOLD}Export SARIF 2.1.0{RESET}           {MUTED}Format findings for GitHub Code Scanning / IDEs{RESET}")
    print(f"  {CORAL}[5]{RESET}  {CREAM_BOLD}Configure MCP Client{RESET}         {MUTED}One-click config for Claude Desktop, Cursor, VS Code{RESET}")
    print(f"  {CORAL}[6]{RESET}  {CREAM_BOLD}Verify SemVer Bump Gate{RESET}      {MUTED}Validate declared version bump against AST findings{RESET}")
    print(f"  {CORAL}[7]{RESET}  {CREAM_BOLD}Launch MCP Stdio Server{RESET}      {MUTED}Run JSON-RPC stdio server for AI agents & editors{RESET}")
    print(f"  {CORAL}[8]{RESET}  {CREAM_BOLD}Inspect Git & Repo Health{RESET}    {MUTED}AST symbol index, languages, and commit history{RESET}")
    print(f"  {CORAL}[q]{RESET}  {MUTED}Exit Athena Studio{RESET}")
    print()


def run_interactive_ui(repo_path: str = ".") -> int:
    """Main interactive terminal UI event loop."""
    _enable_windows_vt100()

    while True:
        git_info = _get_git_status_summary(repo_path)
        print_banner(git_info)
        print_menu()

        try:
            choice = input(f"  {CORAL_BOLD}Athena >{RESET} {CREAM}Choose action [1-8, q] (or press Enter for [1]):{RESET} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {MUTED}Exiting Athena Studio. Goodbye!{RESET}\n")
            return 0

        if not choice:
            choice = "1"

        if choice in ("q", "quit", "exit"):
            print(f"\n  {MUTED}Exiting Athena Studio. Goodbye!{RESET}\n")
            return 0

        print()
        _execute_choice(choice, repo_path)
        print()
        try:
            input(f"  {MUTED}Press Enter to return to main menu...{RESET}")
        except (KeyboardInterrupt, EOFError):
            print()
            return 0


def _execute_choice(choice: str, repo_path: str) -> None:
    """Execute the selected action with rich terminal output cards."""
    if choice == "1":
        print(f"  {CORAL}▶ Running Staged Pre-Commit Gate...{RESET}")
        res = check_staged(repo_path)
        if res.get("status") != "ok":
            print(f"  {RED}✖ Gate Failed:{RESET} {res.get('error_message', res.get('error_code'))}")
            return
        findings = res.get("potential_breaking_changes") or []
        if not findings:
            print(f"  {GREEN}✔ Clean Diff:{RESET} No potential breaking changes found in staged changes.")
            print(f"  {MUTED}Safe to commit.{RESET}")
        else:
            print(f"  {RED}⚠ {len(findings)} Potential Breaking Change(s) Detected:{RESET}")
            for idx, f in enumerate(findings, 1):
                sev = f.get("severity", "medium").upper()
                sev_color = RED if sev == "HIGH" else YELLOW
                print(f"    {idx}. [{sev_color}{sev}{RESET}] {CREAM_BOLD}{f.get('file_path')}{RESET}: {f.get('title')}")
                if f.get("description"):
                    print(f"       {MUTED}{f.get('description')[:120]}{RESET}")

    elif choice == "2":
        print(f"  {CORAL}▶ Detecting Breaking Changes (Working Tree / HEAD vs AUTO base)...{RESET}")
        res = detect_potential_breaking_changes(
            repo_path=repo_path,
            base_ref="AUTO",
            target_ref="HEAD",
            include_low_confidence=False,
            use_llm=False,
        )
        if res.get("status") != "ok":
            print(f"  {RED}✖ Analysis Failed:{RESET} {res.get('error_message', 'Unknown error')}")
            return
        findings = res.get("potential_breaking_changes") or []
        print(f"  {CREAM_BOLD}Analysis Complete:{RESET} {len(findings)} breaking changes identified.")
        print(f"  {MUTED}Base:{RESET} {res.get('base_ref')}  {MUTED}Target:{RESET} {res.get('target_ref')}")
        for idx, f in enumerate(findings[:10], 1):
            sev = f.get("severity", "medium").upper()
            sev_color = RED if sev == "HIGH" else YELLOW
            print(f"    {idx:02d}. [{sev_color}{sev}{RESET}] {CREAM_BOLD}{f.get('file_path')}{RESET}: {f.get('title')}")
        if len(findings) > 10:
            print(f"    {MUTED}... and {len(findings) - 10} more findings. Run option [3] for full HTML report.{RESET}")

    elif choice == "3":
        print(f"  {CORAL}▶ Generating Standalone HTML Breaking Change Report...{RESET}")
        res = detect_potential_breaking_changes(
            repo_path=repo_path,
            base_ref="AUTO",
            target_ref="HEAD",
            include_low_confidence=False,
            use_llm=False,
        )
        html_text = render_html_report(res)
        out_filename = "athena-report.html"
        try:
            with open(out_filename, "w", encoding="utf-8") as f:
                f.write(html_text)
            print(f"  {GREEN}✔ Report Generated:{RESET} {CREAM_BOLD}{os.path.abspath(out_filename)}{RESET} ({len(html_text):,} bytes)")
            print(f"  {MUTED}Open this file in any browser to explore interactive findings, call graphs, and diffs.{RESET}")
        except Exception as exc:
            print(f"  {RED}✖ Failed to save HTML report:{RESET} {exc}")

    elif choice == "4":
        print(f"  {CORAL}▶ Exporting SARIF 2.1.0 Static Analysis Log...{RESET}")
        res = detect_potential_breaking_changes(
            repo_path=repo_path,
            base_ref="AUTO",
            target_ref="HEAD",
            include_low_confidence=False,
            use_llm=False,
        )
        sarif_data = breaking_report_to_sarif(res)
        out_filename = "athena-findings.sarif"
        try:
            with open(out_filename, "w", encoding="utf-8") as f:
                json.dump(sarif_data, f, indent=2)
            runs = sarif_data.get("runs", [{}])[0]
            results_count = len(runs.get("results", []))
            print(f"  {GREEN}✔ SARIF 2.1.0 Exported:{RESET} {CREAM_BOLD}{os.path.abspath(out_filename)}{RESET}")
            print(f"  {MUTED}Total Results:{RESET} {results_count} findings formatted for GitHub Code Scanning / SonarQube.")
        except Exception as exc:
            print(f"  {RED}✖ Failed to export SARIF:{RESET} {exc}")

    elif choice == "5":
        print(f"  {CORAL}▶ Configure MCP Client:{RESET}")
        print(f"    {CREAM}[a]{RESET} Claude Desktop (`claude_desktop_config.json`)")
        print(f"    {CREAM}[b]{RESET} Cursor (`.cursor/mcp.json`)")
        print(f"    {CREAM}[c]{RESET} VS Code (`.vscode/mcp.json`)")
        sub_c = input(f"    {CORAL}Select client [a/b/c]:{RESET} ").strip().lower()
        client_map = {"a": "claude-desktop", "b": "cursor", "c": "vscode"}
        target_client = client_map.get(sub_c, "claude-desktop")
        config_snippet = render_mcp_config(target_client)
        print()
        print(f"  {MUTED}Generated configuration for {target_client}:{RESET}")
        print(f"{CORAL}{config_snippet}{RESET}")

    elif choice == "6":
        declared = input(f"  {CORAL}Enter declared version bump [patch/minor/major]:{RESET} ").strip().lower()
        if declared not in ("patch", "minor", "major"):
            print(f"  {YELLOW}Defaulting declared bump to 'patch'.{RESET}")
            declared = "patch"
        print(f"  {CORAL}▶ Evaluating SemVer bump against AST breaking changes...{RESET}")
        res = semver_check(repo_path, base="AUTO", target="HEAD", declared=declared)
        if res.get("status") != "ok":
            print(f"  {RED}✖ Gate Failed:{RESET} {res.get('error_message')}")
            return
        passed = res.get("gate_passed", False)
        req = res.get("required_bump", "patch")
        if passed:
            print(f"  {GREEN}✔ SemVer Gate PASSED:{RESET} Declared bump '{declared}' satisfies required '{req}'.")
        else:
            print(f"  {RED}✖ SemVer Gate FAILED:{RESET} Declared bump '{declared}' is insufficient for required '{req}'.")
            print(f"  {MUTED}Reason:{RESET} {res.get('reason')}")

    elif choice == "7":
        print(f"  {CORAL}▶ Switching to Athena MCP Stdio Server mode...{RESET}")
        print(f"  {MUTED}Listening for JSON-RPC messages on stdin/stdout. Press Ctrl+C to stop.{RESET}")
        try:
            run_mcp_stdio_server()
        except KeyboardInterrupt:
            print(f"\n  {MUTED}MCP Server stopped.{RESET}")

    elif choice == "8":
        print(f"  {CORAL}▶ Inspecting Git Repository & AST Structure...{RESET}")
        res = inspect_repository(repo_path, max_recent_commits=15)
        if res.get("status") != "ok":
            print(f"  {RED}✖ Inspection Failed:{RESET} {res.get('error_message')}")
            return
        print(f"  {CREAM_BOLD}Primary Language:{RESET} {res.get('primary_language', 'Unknown')}")
        print(f"  {CREAM_BOLD}Total Commits Sampled:{RESET} {len(res.get('recent_commits', []))}")
        tags = res.get("tags") or []
        print(f"  {CREAM_BOLD}Release Tags:{RESET} {', '.join(tags[:5]) if tags else 'None'}")
        ast_files = res.get("ast_index_sample") or []
        if ast_files:
            print(f"  {CREAM_BOLD}Indexed AST Symbols Sample:{RESET}")
            for f in ast_files[:5]:
                print(f"    - {f}")
    else:
        print(f"  {YELLOW}Unknown option '{choice}'. Please select an option from 1 to 8, or 'q' to exit.{RESET}")
