---
name: athena
description: Local-first evidence-backed code knowledge graph, breaking-change AST analyzer, and minimal-diff coding discipline.
---

# Athena Agent Protocol

Before editing or adding code:
1. **Check the graph & map first:** Call `get_repo_map` or `query_code_graph` (or `athena map` / `athena graph query`) instead of blind grep loops.
2. **Trace blast radius & affected tests:** Check callers and signatures before changing public functions, classes, or APIs (`detect_potential_breaking_changes`), and select impacted pytest/Playwright/unit tests (`predict_affected_tests` / `athena affected-tests`).
3. **Minimalism ("Lazy, not negligent"):**
   - Reuse existing helpers/patterns in the repo before writing new code.
   - Never skip trust-boundary validation, error handling, or user-requested features.
   - Leave a small test for non-trivial logic.
   - Mark deliberate deferrals with `# shortcut: <limit>, <when to upgrade>` (tracked via `athena debt`).
4. **Summary-first & Evidence-backed:** Prefer `detail="summary"` and page via `inspect_analysis_view(evidence_id, facet, offset, limit)`. Never claim completeness when `completeness != "complete"`.
