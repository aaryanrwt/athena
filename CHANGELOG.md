# Changelog

All notable changes to Athena are recorded here. The project follows semantic versioning.

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
