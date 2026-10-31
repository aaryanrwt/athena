# Changelog

All notable changes to Athena are recorded here. The project follows semantic versioning.

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
