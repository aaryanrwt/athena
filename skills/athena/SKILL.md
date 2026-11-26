---
name: athena
description: Local-first evidence-backed code knowledge graph, breaking-change AST analyzer, and minimal-diff coding discipline.
---

# Athena Agent Protocol (v1.4.0+)

Before editing or adding code:
1. **Check the graph & map first:** Call `get_repo_map` / read `athena://repo/map` or call `query_code_graph` (or `athena map` / `athena graph . --query "..."`) instead of blind grep loops.
2. **Trace blast radius & affected tests:** Check callers and signatures before changing public functions, classes, or APIs (`detect_potential_breaking_changes` / `athena check --staged`), and select impacted pytest/Playwright/unit tests (`predict_affected_tests` / `athena affected-tests`).
3. **Remediate safely (`athena fix` / `generate_fix_plan`):** Use dry-run unified diffs first (`apply=false`) across Python (including multi-line calls, Google/NumPy/Sphinx docstrings, and forwarding `compat_shim` edits) and Tree-sitter multi-language codebases (TS/JS, Go, Rust, Java, C#, Kotlin, Swift, PHP, C/C++). Apply non-overlapping `safe` fixes (`recursion_fix`, `none_guard`, `caller_update`, `docstring_sync`) while leaving `review_required` shims/migration guides for human approval.
4. **Close the loop with Athena + AI (`athena repair` / `athena verify-fix`):** For semantic breaks (missing required arguments, removed APIs, changed return types), generate bounded caller repair tasks (`prepare_ai_repair_tasks` — zero-key MCP `handoff` or `athena repair --provider claude-code|codex|ollama|hermes|pi|cursor|openai-compat|anthropic`) and verify with real compilers and tests (`athena verify-fix` / `verify_fix`: `py_compile`/mypy/pyright/`go vet`/`cargo check`/`tsc`/`node --check`/`dotnet build`/`php -l` + affected tests + AST re-audit, with automatic snapshot rollback on failure).
5. **Minimalism ("Lazy, not negligent"):**
   - Reuse existing helpers/patterns in the repo before writing new code.
   - Never skip trust-boundary validation, error handling, or user-requested features.
   - Leave a small test for non-trivial logic.
   - Mark deliberate deferrals with `# shortcut: <limit>, <when to upgrade>` (tracked via `athena debt` / `scan_debt`).
6. **Summary-first & Evidence-backed:** Prefer `detail="summary"` and page across sessions via `inspect_analysis_view(evidence_id, facet, offset, limit)` or `athena view <ev_id> --facet ...`. Never claim completeness when `completeness != "complete"`.
7. **Verify token savings & setup:** Inspect local context-reduction telemetry via `get_token_savings_report` / `athena://gain/summary` / `athena gain`, inspect available AI backends via `athena://ai/providers`, prefer `athena mcp --toolsets ... --read-only` across Athena's 18 MCP tools when least-privilege scoping fits, and run `athena doctor` to verify Git, Python, MCP SDK, Tree-sitter, Rust kernels, AI providers, and local toolchains.
