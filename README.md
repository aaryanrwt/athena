<p align="center">
  <img src="assets/banner.png" alt="Athena: Local-First Git & AST Intelligence" width="100%" />
</p>

<h1 align="center">Athena (<code>athena-mcp</code>)</h1>

<p align="center">
  <em>Your git diff says it is safe. Athena checks the callers.</em>
</p>

<p align="center">
  <a href="#before-vs-after-rust-integration">
    <img alt="Athena Telemetry: 100% Offline 0-LLM, Python 3.12-3.15 + Rust, stdio 13 MCP Tools, 14 Languages, Up to 26.7x Graph Speedup" src="assets/athena-pills-white.svg" width="100%" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/aaryanrwt/athena/actions/workflows/athena-audit.yml"><img alt="CI" src="https://github.com/aaryanrwt/athena/actions/workflows/athena-audit.yml/badge.svg?branch=main" /></a>
  <a href="https://github.com/aaryanrwt/athena/releases"><img alt="Release" src="assets/badges/release.svg" /></a>
  <a href="https://github.com/aaryanrwt/athena/stargazers"><img alt="GitHub Stars" src="assets/badges/stars.svg" /></a>
  <a href="https://github.com/aaryanrwt/athena/commits/main"><img alt="Last Commit" src="assets/badges/activity.svg" /></a>
  <a href="LICENSE"><img alt="License" src="assets/badges/license.svg" /></a>
  <br />
  <a href="https://m8ven.ai/mcp/aaryanrwt/athena?s=readme"><img alt="M8ven Score" src="https://m8ven.ai/badge/mcp/aaryanrwt/athena" height="20" /></a>
  <a href="https://hub.xerj.org/contributors/aaryanrwt"><img alt="XERJ Corpus Hub contributor" src="https://hub.xerj.org/contributors/aaryanrwt/badge.svg" height="20" /></a>
</p>

Athena is a **local-first code intelligence tool** (CLI, Terminal UI, and MCP server). It runs offline on your machine—no cloud APIs or vector databases required—to help both developers and AI coding agents:

1. **Catch breaking changes before you merge** (renamed/removed symbols, parameter shifts, unguarded `None` defaults, unit-shift hints, recursion bugs, and broken callers).
2. **Map and query any codebase in seconds** (`athena graph` & `athena map`), cutting agent token usage by **49x–3,025x** on real repositories.
3. **Predict affected tests & track technical debt** (`athena affected-tests` for pytest/Playwright + `athena debt` for `# shortcut:` markers).
4. **Plug into any AI coding agent** (`athena install`)—Hermes, OpenClaw, Claude Code, Codex, Cursor, and Pi—with safe, backed-up configs and optional **Hybrid Rust acceleration**.

## Table of Contents

- [Quickstart](#quickstart)
- [Everyday Commands](#everyday-commands)
- [How It Works](#how-it-works)
- [Project & Folder Architecture](#project--folder-architecture)
- [Real-World Benchmark (v1.3.1)](#real-world-benchmark-v131)
- [Before vs. After Rust Integration](#before-vs-after-rust-integration)
- [Use It in GitHub Actions](#use-it-in-github-actions)
- [Star History](#star-history)
- [Further Reading](#further-reading)

---

## Quickstart

```bash
git clone https://github.com/aaryanrwt/athena.git
cd athena
pip install -e .

# Open the interactive Terminal Studio
athena ui

# Get a <=2KB architectural map of any repo
athena map .

# Check for breaking changes before committing
athena check --staged
```

---

## Everyday Commands

| Command | What it does |
| :--- | :--- |
| `athena ui` | Launches the interactive terminal studio (auto-starts when run in a terminal). |
| `athena map .` | Prints a `<=2000`-character export map of shared modules and symbols. |
| `athena graph . --query "auth"` | Builds/queries `.athena/graph.json` with trigram search + hub-guarded BFS. |
| `athena breaking-changes . --base main --target HEAD` | Finds potential breaking API changes, caller impact, and doc drift. |
| `athena check --staged` | Pre-commit gate: exits non-zero if staged changes break public APIs. |
| `athena affected-tests .` | Predicts pytest, Playwright `.spec.ts`, and unit tests impacted by a diff. |
| `athena debt .` | Lists `shortcut: <limit>, <when to upgrade>` debt markers with AST symbols. |
| `athena install --agent hermes` | Installs Athena skills/hooks for `hermes`, `openclaw`, `claude-code`, `codex`, `cursor`, or `pi`. |
| `athena init-mcp cursor` | Generates ready-to-paste MCP config JSON (`claude-desktop`, `cursor`, `vscode`). |

---

## How It Works

```mermaid
flowchart LR
    User["Developer / AI Agent\n(CLI, Studio UI, MCP)"] --> Gate["Security & Redaction Gate\n(Path Jail, Secret Redaction)"]
    Gate --> Git["Git & AST Engine\n(14 Languages, 0-LLM Default)"]
    Gate --> Graph["Code Graph & Repo Map\n(.athena/graph.json, <=2KB Map)"]
    Git --> Evidence["Evidence Store\n(ev_<sha256> & unk_<sha256>)"]
    Graph --> Evidence
    Evidence --> Output["Verified Output\n(Paged Views, SARIF, HTML, Release Notes)"]
```

- **Zero-LLM by default:** Everything runs deterministically offline. Local Ollama (`qwen2.5-coder:7b` / `gemma:latest`) is strictly optional (`--llm`).
- **Never fakes completeness:** Unresolved dynamic calls (`getattr`, `eval`, oversized files) are tracked explicitly as `ResidualUnknown` (`unk_<sha256>`) records instead of being hidden.
- **Context-friendly MCP:** Heavy tools support `detail="summary"` and return a `parent_evidence_id` that agents can page through with `inspect_analysis_view`.

---

## Project & Folder Architecture

```text
athena/
├── src/athena/
│   ├── cli.py                # CLI entry point (ui, mcp, graph, map, affected-tests, debt, install, check, report, semver-check)
│   ├── tui.py                # Interactive Athena Studio Terminal UI
│   ├── mcp_server.py         # 13-tool stdio MCP server with ToolAnnotations & hot/cold discovery
│   ├── git_inspector.py      # Safe git diff & batched cat-file extractor (GIT_NO_LAZY_FETCH=1, TOCTOU drift guard)
│   ├── ast_analyzer.py       # Python ast contract/unit-shift/recursion differ + 14-language structural scanner
│   ├── graph_store.py        # Persistent .athena/graph.json builder, TS barrel/PHP/CUDA/TeX graph & atomic snapshots
│   ├── graph_query.py        # Trigram+IDF scorer, hub-guarded BFS, god_nodes & shortest_path
│   ├── test_selector.py      # Predictive test selection (pytest, Playwright .spec.ts/.e2e.ts, unit tests)
│   ├── repo_map.py           # <=2KB zero-search architectural export map
│   ├── debt_tracker.py       # AST-bound `shortcut:` technical debt scanner
│   ├── evidence_store.py     # Canonical ev_<sha256> & unk_<sha256> store + paged inspection
│   ├── agent_installer.py    # Transactional installer for Hermes, OpenClaw, Claude Code, Codex, Cursor & Pi
│   ├── gates.py              # Staged pre-commit & SemVer bump gates
│   ├── sarif.py              # SARIF 2.1.0 exporter
│   ├── html_report.py        # CSP-hardened single-file HTML report renderer
│   ├── release_notes.py      # Deterministic & optional Ollama release-note pipeline
│   ├── ollama_engine.py      # Optional local Ollama integration (gemma:latest / qwen2.5-coder:7b)
│   ├── symbol_cache.py       # Content-addressed parsed symbol cache
│   ├── mcp_config.py         # MCP client config generator (Claude Desktop, Cursor, VS Code)
│   ├── verifier.py           # Ground-truth evidence verifier & hallucination guard
│   ├── security.py           # Path jail, symlink defense, NTFS ADS guard & Rust-accelerated secret redaction
│   ├── _fast_kernels.py      # Plain-data hot kernels with verified Rust PyO3 fast-anything ports
│   └── models.py             # Pydantic v2 schemas
├── skills/athena/SKILL.md    # Portable Athena agent protocol skill
├── docs/                     # CLI examples, evaluation reports, CI/Docker integrations & demo tape
├── tests/                    # Automated unit, MCP stdio, release-readiness & evaluation suites
├── .github/                  # CI workflows (athena-audit, action-smoke) & PR comment renderer
├── action.yml                # Reusable GitHub Action
├── Dockerfile                # Rootless container image
└── pyproject.toml            # Package & Python 3.12-3.15 metadata
```

---

## Real-World Benchmark (v1.3.1)

Tested offline across **13 new repositories** (**3 NVIDIA 2026 & CUDA repos** over `1,000+` commits + **10 diverse high-star repos** across JS, TS/Go, Rust, C/C#, Kotlin, Ruby, PHP, TeX): **13/13 passed with 0 errors**.

| Repository | Language | Stars | Span | Files | Nodes / Edges | Cold -> Warm Cache | Token Reduction |
| :--- | :--- | ---: | :--- | ---: | ---: | ---: | ---: |
| `NVIDIA/auto-ontology` | Python (2026) | 14,568 | `HEAD~1000` | 897 | 7,486 / 23,258 | 33.3s -> 1.9s | **618.6x** |
| `NVIDIA/NeMo-Relay` | Rust (2026) | 257 | `HEAD~1000` | 1,560 | 32,331 / 48,324 | 82.3s -> 6.7s | **3,025.0x** |
| `NVIDIA/cuvs` | CUDA / C++ | 903 | `HEAD~1000` | 1,269 | 6,148 / 7,184 | 34.2s -> 1.8s | **1,330.2x** |
| `facebook/react` | JavaScript | 252,934 | `HEAD~100` | 4,161 | 20,714 / 19,216 | 236.8s -> 12.5s | **1,453.0x** |
| `microsoft/PowerToys` | C / C# | 141,325 | `HEAD~100` | 2,415 | 9,088 / 6,780 | 128.3s -> 6.3s | **1,258.6x** |
| `microsoft/TypeScript` | TypeScript / Go | 111,875 | `HEAD~100` | 503 | 7,879 / 7,907 | 29.3s -> 2.8s | **1,052.1x** |
| `fatedier/frp` | Go | 110,732 | `HEAD~100` | 247 | 2,653 / 2,436 | 11.7s -> 1.0s | **250.3x** |
| `denoland/deno` | Rust | 109,038 | `HEAD~100` | 1,697 | 33,010 / 35,688 | 107.6s -> 8.6s | **2,411.5x** |
| `laravel/laravel` | PHP / Blade | 85,480 | `HEAD~1000` | 24 | 81 / 69 | 1.4s -> 0.2s | **4.4x** |
| `rails/rails` | Ruby | 59,182 | `HEAD~1000` | 3,099 | 20,635 / 19,311 | 129.3s -> 12.0s | **1,335.2x** |
| `JetBrains/kotlin` | Kotlin | 53,614 | `HEAD~100` | 4,406 | 16,278 / 12,611 | 183.1s -> 9.7s | **1,794.9x** |
| `dotnet/runtime` | C# | 18,461 | `HEAD~100` | 4,334 | 18,661 / 14,424 | 229.6s -> 11.4s | **1,978.0x** |
| `latex3/latex2e` | TeX | 2,523 | `HEAD~1000` | 154 | 561 / 393 | 9.8s -> 0.4s | **1,527.1x** |

## Before vs. After Rust Integration

Athena keeps its Python CLI, MCP server, Pydantic schemas, and Python `ast` precision intact (`pip install athena-mcp` works anywhere with pure-Python fallback), while porting its hottest pure kernels to Rust PyO3 extensions via [`EL4CTEO/fast-anything`](https://github.com/EL4CTEO/fast-anything) and batching Git blob reads (`git cat-file --batch`).

### 3-Company `1,000+` Commit Before vs. After Quality & Parity Audit

Verified side-by-side (`FAST_ANYTHING_DISABLE=1` pure Python vs. Rust PyO3 enabled) across **NVIDIA**, **Google**, and **Microsoft** repositories over **`1,000–1,472` commits** each (`HEAD~1000..HEAD`):

| Company & Repo | Span (`HEAD~1000..HEAD`) | Scale (`Files / Nodes / Edges`) | Graph Build (Before -> After) | 20 Queries (Before -> After) | Total Pipeline (Before -> After) | Quality & SHA-256 Parity |
| :--- | :--- | :--- | ---: | ---: | ---: | :--- |
| **NVIDIA** (`NVIDIA/cuvs`) | **1,472 commits** (`8b03db68..0bc18670`) | `1,269 / 6,152 / 7,188` | 29.89s -> **1.33s (`22.48x`)** | 6.04s -> **0.74s (`8.19x`)** | 89.49s -> **28.78s (`3.11x`)** | **14/14 checks identical** (`21` breaks, `306` tests, `ev_ddbf63fa...5b07d`) |
| **Google** (`google/flatbuffers`) | **1,000 commits** (`e08da4de..5eb190f0`) | `1,196 / 11,954 / 19,419` | 43.39s -> **1.62s (`26.73x`)** | 3.22s -> **2.21s (`1.46x`)** | 74.31s -> **24.12s (`3.08x`)** | **14/14 checks identical** (`34` breaks, `831` tests, `ev_c1075fe1...f9fe6`) |
| **Microsoft** (`microsoft/playwright-python`) | **1,000 commits** (`f6726115..c830b5f8`) | `725 / 12,176 / 100,818` | 45.78s -> **12.22s (`3.75x`)** | 14.90s -> 15.96s (`0.93x`*) | 112.03s -> **87.93s (`1.27x`*)** | **14/14 checks identical** (`18` breaks, `604` tests, `ev_dacea634...74a8`) |

*\*Note on `microsoft/playwright-python`: it is predominantly `.py` files (Python `ast.parse` stays in Python) with `100,818` edges iterated in Python's `_build_adj` on each query (`14.90s -> 15.96s`); in that single run, Python's `run_breaking_change_detection` took `35.89s -> 52.27s` due to cold/warm Windows `git.exe`/OS cache variance on Python AST diffs while `predict_affected_tests` dropped `15.47s -> 7.48s` (`2.07x`), yielding `1.27x` total.*

- **0 bugs / 0 regressions introduced by Rust:** Every single SHA-256 `graph_evidence_id`, `completeness` status, node/edge/unknown count, community label, 20 query subgraphs, breaking-change finding list, doc drift count, and predicted test list matched bit-for-bit across all 3 enterprise repositories.
- **Verified Kernel Micro-Benchmarks (`fast-anything verify`) & Batch Git:** `redact_secrets` **41x** (`237.3us -> 5.8us`, `776/776`), `score_graph_trigrams` **8.8x** (`37.3ms -> 4.2ms`, `330/330`), `compute_community_assignments` **3.5x** (`9.6ms -> 2.7ms`, `206/206`), `extract_structural_symbols_raw` **1.9x** (`16.2us -> 8.6us`, `800/800`), plus batched `git cat-file --batch` cutting Athena (`v1.0.0..v1.3.1`) breaking-change analysis **4.02x** (`12.74s -> 3.17s`). (`parse_unified_diff_raw` matched `229/229` calls but measured `3.1x` slower via PyO3 FFI allocation overhead, so it was intentionally kept in Python.)

```bash
# Optional: compile native Rust accelerations locally into .fast/lib/
python scripts/build_rust_accel.py

# Toggle pure-Python fallback at any time
FAST_ANYTHING_DISABLE=1 athena graph . --query "auth"
```

Full version-by-version test history (`v1.0.0` -> `v1.3.1`) and Rust parity audit: [docs/evaluation.md](docs/evaluation.md).

---

## Use It in GitHub Actions

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    fetch-depth: 0
- uses: aaryanrwt/athena@v1.3.1
```

Posts one sticky breaking-change & blast-radius summary per PR. See [docs/integrations.md](docs/integrations.md) for Docker, pre-commit, and permissions setup.

---

## Star History

<p align="center">
  <a href="https://github.com/aaryanrwt/athena/stargazers">
    <img alt="Athena Star History" src="assets/star-history.svg" width="100%" />
  </a>
</p>

---

## Further Reading

- [CLI Examples](docs/cli-examples.md)
- [Benchmarks & Evaluation](docs/evaluation.md)
- [CI, Docker & Pre-Commit Integrations](docs/integrations.md)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

**Maintainer:** Aaryan Rawat ([`aaryan28rwt@gmail.com`](mailto:aaryan28rwt@gmail.com)) · Licensed under [Apache-2.0](LICENSE).
