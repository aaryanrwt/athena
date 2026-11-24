# Changelog

All notable changes to Athena are recorded here. The project follows semantic versioning.

## 1.3.2

### Added & Fixed

- **MCP Resources, URI Templates & Guided Workflow Prompts (`src/athena/mcp_server.py`)**:
  - Exposed read-only MCP Resources (`athena://server/capabilities`, `athena://repo/map`, `athena://evidence/recent`) and URI Template (`athena://evidence/{evidence_id}`) across MCP `1.x` (`1.26+`) and `2.x` servers.
  - Added three built-in workflow prompts (`pre_merge_audit`, `release_readiness_review`, `codebase_onboarding`) plus human-friendly `title` metadata on all 13 MCP tools and structured recovery hints (`retryable`, `remediation_action`, `error_kind`) on errors.
- **Scoped Toolsets, Read-Only Mode & Local `streamable-http` Transport (`athena mcp`, `src/athena/mcp_server.py`)**:
  - Added `--toolsets` (`git,graph,analysis,release,debt,testing,evidence,meta` or `all`) and `--read-only` to `athena mcp` / `create_mcp_server(...)`, restricting exposed tools cleanly at startup.
  - Added `--transport {stdio,streamable-http}`, `--host`, `--port`, and `--allow-remote` with loopback binding enforced by default (`127.0.0.1` / `localhost` / `::1`) to block accidental remote exposure.
- **Cross-Process Disk-Backed `EvidenceStore` (`src/athena/evidence_store.py`, `cli.py`)**:
  - Persists `ev_<sha256>` evidence bundles atomically to `~/.athena/evidence` (or `$ATHENA_EVIDENCE_DIR`) with regex path-traversal validation and bounded LRU disk pruning, enabling separate CLI `athena view <ev_id> --facet ...` calls after `--detail summary`.
  - Added `--detail {complete,summary}` to `athena analyze`, `athena breaking-changes`, and `athena graph`, and forwarded `detail` through `analyze_change_graph` and `verify_breaking_and_doc_drift`.
- **Bounded Pagination, Strict Input Validation & `athena doctor` (`debt_tracker.py`, `test_selector.py`, `repo_map.py`, `cli.py`)**:
  - Added `--offset` and `--limit` (`has_more`, `partial`) pagination across `scan_shortcut_debt`, `predict_affected_tests`, `athena debt`, `athena affected-tests`, and their MCP tools.
  - Applied uniform error recovery classification (`_attach_error_recovery()`) across report-returning MCP tools (`inspect_repository`, `analyze_git_history`, `generate_release_notes`, `detect_potential_breaking_changes`) and strict `INVALID_OFFSET` / `INVALID_LIMIT` validation in `EvidenceStore.inspect_view()`.
  - Fixed multi-megabyte diff-hunk timeout & slow regex/walker scaling (`src/athena/git_inspector.py`, `src/athena/ast_analyzer.py`): bounded pre-redaction hunk slicing in `_parse_unified_diff_by_file` and added precompiled doc-drift/dynamic-call regex guards with fast substring checks plus `O(1)` `commit_by_file` indexing, eliminating `>300s` timeouts on `meta-llama/llama-stack` (`48.44s` pure Python / `37.57s` hybrid Rust) and achieving `6.02x–17.92x` breaking-change speedups vs `v1.3.1` across five `1,050+`-commit repositories (`google/go-github`, `ml-explore/mlx`, `openai/openai-python`, `meta-llama/llama-stack`, `microsoft/semantic-kernel`).
  - Fixed `build_repo_map` to reject non-positive `max_chars` (`INVALID_MAX_CHARS`) and fixed `cli.py` exit codes on `map`, `debt`, and `affected-tests`.
  - Added `athena doctor [repo_path]` for live Python, Git, MCP SDK, Rust kernel (`fast-anything`), evidence store, symbol cache, and repository diagnostics.

## 1.3.1

### Added & Fixed

- **`WORKING_TREE` Stat-First TOCTOU Drift Detection (`src/athena/git_inspector.py`, `release_notes.py`)**: Records `(st_mtime_ns, st_size)` when reading `WORKING_TREE` blobs and re-stats touched files before returning, emitting an explicit drift warning if files changed mid-flight.
- **Unit-Shift Heuristic on `behavior_changed` (`src/athena/ast_analyzer.py`)**: Flags possible unit-scaling shifts (e.g., milliseconds vs. seconds on `timeout`/`delay`/`ttl` parameters) when parameter types remain compatible.
- **Multi-Hop TS/JS Barrel Re-Exports (`src/athena/graph_store.py`)**: Resolves `export { ... } from '...'` and `export * from '...'` plus directory `index` stems so consumer -> barrel -> target edges connect in `CodeGraph`.
- **PHP/Laravel Dynamic Magic `ResidualUnknown` Tracking (`src/athena/graph_store.py`)**: Flags `__callStatic`, `__call`, `->bind(`, `->singleton(`, and `app()->make(` as `ResidualUnknownRecord(kind="dynamic_dispatch")` so Laravel/PHP graphs accurately report `completeness="partial"`.
- **Predictive Test Selection (`src/athena/test_selector.py`, `athena affected-tests`, `predict_affected_tests`)**: Maps diffed files and AST symbols to impacted pytest, Playwright (`.spec.ts`/`.e2e.ts`), and unit test suites.
- **CUDA & TeX Language Support (`src/athena/graph_store.py`)**: Added `.cu`/`.cuh` (`__global__`/`__device__`/`__host__` kernels) and `.tex` (`\section`/`\newcommand`) structural extraction.
- **Hybrid Rust PyO3 Acceleration & Batched Git Blob Reads (`src/athena/_fast_kernels.py`, `.fast/ports/`, `scripts/build_rust_accel.py`)**:
  - Replaced per-file `git cat-file -s` + `git show` calls with batched binary `git cat-file --batch-check` + `cat-file --batch` (`read_blobs_at_revision`), cutting `athena` (`v1.0.0..v1.3.1`) breaking-change analysis **4.02x** (`12,737 ms -> 3,170 ms`).
  - Accelerated `redact_secrets` (`41x`, `776/776`), `score_graph_trigrams` (`8.8x`, `330/330`), `compute_community_assignments` (`3.5x`, `206/206`), and `extract_structural_symbols_raw` (`1.9x`, `800/800`) via verified Rust crates generated with `EL4CTEO/fast-anything`, with automatic pure-Python fallback (`FAST_ANYTHING_DISABLE=1`).
  - Audited across 3 tech-company repositories over `1,000–1,472` commits each (`NVIDIA/cuvs`, `google/flatbuffers`, `microsoft/playwright-python`) in [`tests/test_rust_parity.py`](tests/test_rust_parity.py) and live A/B runs: **14/14 parity checks identical** (`0` bugs / `0` regressions), up to **`26.73x`** faster graph builds.

## 1.3.0

### Added

- **Persistent, Incremental Code Knowledge Graph (`athena graph`, `query_code_graph`)**: Zero-LLM AST + bounded structural code graph (`.athena/graph.json`) with SHA-256 incremental file caching, deterministic community clustering, trigram+IDF + hub-guarded BFS querying (`token_budget=2000`), non-blocking `GraphSnapshotManager` atomic reload, and default test/utility down-weighting in `god_nodes`.
- **Cryptographic Content-Addressed Evidence & Residual Unknowns (`src/athena/evidence_store.py`)**: Canonical `ev_<sha256>` IDs, durable `ResidualUnknownRecord` (`unk_<sha256>`) tracking for dynamic dispatch (`getattr`/`eval`/oversized/partial parses), strict `resolve_completeness` (never defaults to `complete`), `detail="summary" | "complete"` retained-evidence paging (`inspect_analysis_view`, `athena view`), and `discover_tools` progressive catalog metadata.
- **Zero-Search Codebase Map & `shortcut:` Debt Ledger (`athena map`, `get_repo_map`, `athena debt`, `scan_debt`)**: `<=2000`-char prompt-injection-sanitized architectural export map and AST-bound `shortcut: <limit>, <when to upgrade>` debt scanner.
- **Transactional Cross-Agent Installer (`athena install`, `src/athena/agent_installer.py`)**: SHA-256-backed transactional setup with readback verification for `hermes`, `openclaw`, `claude-code`, `codex`, `cursor`, and `pi` (session-scoped hooks, UTF-8 safe stdin, no inline `node -e`).
- **Python 3.15 Support & v1.3.0 Benchmark/Mutation Harness**: Verified on Python 3.15.2 with `tests/evaluation/run_v13_benchmark.py`.

## 1.2.0

### Added

- `athena ui` launches an interactive Studio Terminal UI with retro modular block typography, warm terracotta/coral palette, live Git status indicators, and one-click actions.
- Automatic interactive TTY detection: running `athena` in an interactive terminal opens Athena Studio UI, while non-interactive piped execution seamlessly routes to the MCP JSON-RPC stdio server.
- `athena init-mcp {claude-desktop,cursor,vscode}` prints ready MCP client configuration JSON; `--write --path <file>` writes it and never overwrites an existing file without `--force`.
- `athena breaking-changes --format sarif` emits SARIF 2.1.0 with repository-relative paths and evidence-backed results.
- `athena check --staged` deterministically analyzes staged changes against HEAD and exits non-zero when potential breaking changes are found (pre-commit friendly; no refs, index, or files are modified).
- `athena report --html` renders a single-file static HTML breaking-change report (all content redacted and escaped, no scripts or external assets).
- `athena semver-check --base --target --declared {major,minor,patch}` computes the required bump and exits 1 when the declared bump is too small (exit 2 on analysis errors).
- Opt-in incremental parsed-symbol cache keyed by file content hash: `--cache-dir <dir>` or `ATHENA_CACHE_DIR`. Corrupt, mismatched, or oversized entries are treated as misses; keys are fixed-format hex digests so paths cannot traverse.
- Fixed Pydantic validation error in `SymbolSignatureChange` when recursive functions produce `behavior_changed` defects.
- `pytest-timeout` added to dev dependencies; the stdio MCP round-trip test now has a timeout.

## Unreleased

### Security

- Disabled Git text-conversion helpers, external diff execution, interactive credential prompts, and implicit lazy object fetching during analysis.
- Added recursive report redaction for credentials found in AST signatures, evidence, caller snippets, JSON responses, and generated Markdown.
- Added safe release-output creation, atomic approved overwrites, hard-link protection, and Git metadata path blocking.
- Corrected MCP annotations for optional file writes and optional Ollama network access.
- Redacted credentials embedded in service URLs and exception messages before MCP or Ollama failures are serialized.
- Pinned GitHub Actions to immutable reviewed commits and added dependency auditing plus a CycloneDX SBOM artifact.

### Reliability

- Isolated committed revision analysis from dirty or newer working-tree files.
- Converted required Git extraction and tree-enumeration failures into structured errors.
- Restored MCP 1.26 compatibility while supporting MCP 2.x.
- Made live Ollama tests explicitly opt-in and expanded CI across Python 3.12, 3.13, and 3.14.

### Credit

Athena was created and is maintained by **Aaryan Rawat**.

The October 2026 security audit and remediation was contributed by **[Gh0stlyKn1ght](https://github.com/Gh0stlyKn1ght)**.

## 1.1.0

- Added multi-language structural analysis, recursive-call analysis, evidence-backed release notes, and the v1.1 evaluation corpus.
