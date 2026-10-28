# Security Policy

## Supported Versions

The following versions of **Athena (`athena-mcp`)** are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| `1.1.x` | :white_check_mark: |
| `1.0.x` | :white_check_mark: |
| `< 1.0` | :x:                |

---

## Built-In Security Guarantees

Athena is designed as a **local-first** MCP server and CLI. Analysis tools are read-only; release tools can write only to an explicitly requested output path:

- **Path Jail & Symlink Escape Defense (`src/athena/security.py`)**: All repository paths and file inspections are canonicalized and confined to the target Git workspace.
- **Git CLI Flag Injection Defense**: Revision references (`base_ref`, `target_ref`) beginning with `-` or containing unsafe control characters are rejected before invoking `git` subprocesses (`shell=False`).
- **Secret & Token Redaction**: Diff excerpts and commit metadata are automatically scrubbed for API keys, Bearer tokens, private keys, and credentials prior to MCP serialization or optional local Ollama prompts.
- **No Implicit Git Network Calls**: Git analysis disables lazy object fetching, interactive credential prompts, external diff drivers, and text-conversion helpers. Optional Ollama analysis contacts only the explicitly configured Ollama URL when enabled.
- **Revision Isolation**: Committed targets are read from their resolved Git object IDs. Filesystem content is used only for an explicit `WORKING_TREE` target.
- **Complete Output Redaction**: Serialized reports and generated Markdown are recursively redacted, including AST-derived signatures and caller snippets.
- **Failure-Path Redaction**: MCP and Ollama error details redact provider tokens, authorization values, and credentials embedded in service URLs before serialization.
- **Safe Explicit Writes**: Release output rejects Git metadata paths, uses exclusive creation by default, and uses atomic replacement for approved overwrites.
- **Hardened CI Supply Chain**: GitHub Actions are pinned to reviewed commit SHAs. CI audits installed dependencies, builds a wheel, and publishes a CycloneDX SBOM with the package artifacts.

## Residual Security Boundaries

- Athena is a static analyzer, so it cannot prove the runtime behavior of analyzed code or resolve every reflective/dynamic call. Reports expose coverage and confidence instead of treating those gaps as verified-safe behavior.
- Atomic output replacement prevents hard-link mutation and the ordinary validation/write race. Athena cannot fully defend against another hostile process that already has permission to rename or replace parent directories during the write; callers should analyze repositories owned by the same trusted user.
- Enabling Ollama sends bounded, redacted repository context to the configured Ollama endpoint. Operators are responsible for trusting that endpoint and its host.
- Blobless and partial clones must have the requested objects available locally. Athena reports missing objects instead of silently fetching them; an operator may fetch them separately after reviewing the configured remote.

## Project Credit

Athena was created and is maintained by **Aaryan Rawat** (`aaryan28rwt@gmail.com`). Security fixes and reports should preserve this project attribution.

## Security Audit Credit

The October 2026 adversarial security review and remediation was contributed by
**[Gh0stlyKn1ght](https://github.com/Gh0stlyKn1ght)**. The review covered Git helper
execution, revision integrity, credential redaction, safe output handling, MCP
capability declarations, dependency auditing, SBOM generation, and CI action pinning.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Athena (for example: path traversal, Git argument injection, symlink escape, or credential redaction bypass):

1. **Please do NOT open a public GitHub issue** for exploitable security vulnerabilities.
2. Report the vulnerability privately via **[GitHub Private Vulnerability Reporting](https://github.com/aaryanrwt/athena/security/advisories/new)** or directly to the project owner & maintainer (**Aaryan Rawat** — `aaryan28rwt@gmail.com`).
3. Include:
   - Affected file(s) and commit SHA (`git rev-parse HEAD`).
   - A minimal proof-of-concept reproduction.
   - Potential impact and suggested remediation (if any).

We will acknowledge receipt within **48 hours** and work with you to validate, patch, and credit your finding in the security advisory.
