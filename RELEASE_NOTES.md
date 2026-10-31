> **"Your git diff says it's safe. Athena checks the callers."**

When you tweak a function signature, delete an argument, or narrow a return type in a pull request, your git diff only tells you what changed in that one file. It doesn't warn you about the callers in three other directories that just broke.

**Athena v1.2.0** solves this locally. It reads your git history, parses real ASTs across 14 languages, maps downstream callers, and gives you evidence-backed breaking change alerts—deterministically, with zero LLM dependency.

Here is everything shipping in v1.2.0.

---

### 🚀 What's New in v1.2.0

#### 1. Athena Studio Terminal UI (`athena ui`)
You don't need complex command flags to see what's happening. Run `athena ui` in any repository to launch the interactive terminal studio:
- **Live Git Context**: Shows your active branch, HEAD commit, staged changes, and working tree status at a glance.
- **One-Key Actions**: Press `1` to run a pre-commit check on staged files, `2` to scan your branch for breaking changes, `3` to render an HTML report, or `5` to generate your MCP configuration.
- **Dual-Mode Ergonomics**: Run `athena` in an interactive terminal to get the studio dashboard; pipe it into an editor or agent and it silently routes to the JSON-RPC stdio MCP server.

#### 2. One-Click MCP Client Configs (`athena init-mcp`)
Connecting Athena to your editor takes five seconds:
```bash
# Print or write configuration for your favorite editor
athena init-mcp cursor
athena init-mcp claude-desktop
athena init-mcp vscode
```

#### 3. SARIF 2.1.0 Code Scanning Export
Export breaking change findings in standard SARIF format for GitHub Code Scanning, SonarQube, or your CI annotations:
```bash
athena breaking-changes . --base main --target HEAD --format sarif
```

#### 4. Pre-Commit Breaking Change Gate (`athena check --staged`)
Catch breaking API changes before they even hit your commit log. Add it as a pre-commit hook (`.pre-commit-hooks.yaml`) or run it manually:
```bash
athena check --staged
```

If you stage a breaking signature change, Athena flags the exact line and exits with status 1—without modifying any files or git refs.

#### 5. Standalone Single-File HTML Reports (`athena report --html`)
Need to share a breaking-change review with your team? Athena can bundle its visual call graph, impacted caller trees, and unified diff citations into a single self-contained HTML file:
```bash
athena report . --html --output athena-report.html
```

Zero external scripts, zero CDNs, completely offline.

#### 6. Automated SemVer Bump Gate (`athena semver-check`)
Never accidentally release a breaking change under a patch or minor version bump:
```bash
athena semver-check . --declared patch
```

If your changes contain breaking signature mutations, Athena fails the check and tells you the minimum SemVer bump required.

#### 7. Incremental Content-Hash Symbol Cache (`--cache-dir`)
Speed up repeat runs across large monorepos. Athena hashes file contents via SHA-256 and caches parsed symbols, eliminating redundant AST re-parsing.

#### 8. Real-World Engine Hardening
- Strengthened detection for recursive function defects (unconditional recursion without base cases, broken self-recursion arity).
- Fixed schema validation for behavioral function mutations.
- Multi-language coverage across Python, TypeScript, JavaScript, C++, C, Go, Rust, Java, C#, Ruby, and PHP.

---

### 📊 Real-World Testing & Verification

Athena's release criteria are backed by real, unvarnished numbers from real-world open-source codebases:

- **158 Automated Tests**: 157 offline deterministic tests + 1 live Ollama integration test (100% green).
- **55-Repository Multi-Language Benchmark**: 100% pass rate across 11 languages over 5,500 commits, 10,680 diff hunks, and 411 recursive functions.
- **Top-Tier Scale Corpus**: Evaluated against top GitHub projects representing over 8.3 million cumulative stars, verifying deterministic caller blast-radius extraction across real commit histories.
- **5-Pass Consistency Verification**: Repositories tested across 5 consecutive passes to confirm zero finding drift and identical hash invariance across runs.

---

### 📦 Quickstart

Install directly from source:

```bash
# Clone and install locally
git clone https://github.com/aaryanrwt/athena.git
cd athena
pip install -e .

# Launch the interactive Studio UI
athena ui

# Or configure your MCP client
athena init-mcp cursor
```

**Maintainer**: Aaryan Rawat ([aaryan28rwt@gmail.com](mailto:aaryan28rwt@gmail.com))
