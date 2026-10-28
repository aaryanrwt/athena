<p align="center">
  <img src="assets/banner.png" alt="Athena — Local-First Git & AST Intelligence" width="100%" />
</p>

<br />

# Athena (`athena-mcp`) — v1.1.0

[![M8ven Score](https://m8ven.ai/badge/mcp/aaryanrwt/athena)](https://m8ven.ai/mcp/aaryanrwt/athena?s=readme)

**Local-First, Evidence-Backed Multi-Language Git & AST Release-Readiness and Change-Intelligence MCP Server**

- **Version**: `1.1.0`
- **Owner & Maintainer**: **Aaryan Rawat** ([`aaryan28rwt@gmail.com`](mailto:aaryan28rwt@gmail.com))

Athena is an open-source, local-first Model Context Protocol (MCP) server and developer CLI that delivers **verifiable, ground-truth code-change intelligence**. By combining deterministic Git diff analysis (`100+` commit range inspection), Python Abstract Syntax Tree (`ast`) and multi-language structural signature comparison (**TypeScript, JavaScript, Python, C++, C, Go, Rust, Java, Kotlin, Scala, C#, Ruby, PHP, Swift**), downstream caller blast-radius tracing, and documentation-drift detection, Athena eliminates the hallucination and superficiality of conventional release-note generators.

<p align="center">
  <img src="assets/athena-brag.gif" alt="Athena in Action — AST & Git Change Intelligence Showcase" width="100%" />
</p>

---

## Key Differentiators (v1.1.0)

1. **Deterministic-First Core (100% LLM-Independent)**: Athena works out-of-the-box completely offline without Ollama, without an external API, and without any network connection. All Git inspections, AST symbol deltas, caller blast-radius graphs, doc-drift warnings, and release notes execute deterministically with 0ms LLM wait time.
2. **Multi-Language Structural & AST Diffing (New in v1.1.0)**: Full Python `ast` contract and recursion analysis plus structural symbol & signature comparison across **TypeScript, JavaScript, C++, C, Go, Rust, Java, Kotlin, Scala, C#, Ruby, PHP, and Swift** — detecting removed public symbols, parameter additions/removals, visibility narrowing, and return-type mutations across 100+ commit histories.
3. **Ground-Truth Evidence Citations**: Every reported change story and potential breaking change is bound to verified `EvidenceRecord` items containing the 40-character commit SHA, commit subject, file path, exact base/target line spans, unified diff hunk header/excerpt, and confidence rating.
4. **AST Contract Differencing & Recursive Function Defect Analysis**: Athena ignores misleading Conventional Commit prefixes (e.g. `fix:` commit messages that actually introduce new public methods or break signatures). It analyzes parameter defaults, positional-parameter index shifts (`BUG-030`), `None`-fallback body guards (`griffe#469`), return-type annotations, `(str, Enum)` <-> `StrEnum` migrations (`griffe#501`), Enum members, public constants, newly raised exceptions (`griffe#498`), and **recursive function bugs** (broken recursive self-call arity, unconditional infinite recursion without a base case, unqualified class-method self-recursion `NameError`s, and self-recursive caller blast radius).
5. **Public API Exposure Differentiation**: Automatically distinguishes symbols exported via `__all__`, package `__init__.py` re-exports, TypeScript `export` declarations, Go exported identifiers, Rust `pub` items, and Java/C#/C++ `public` symbols (`is_public_api_export=True`) from internal/private helpers (`is_public_api_export=False`) so teams know when external package consumers are at risk even if internal callers look clean.
6. **Unresolved Dynamic Dispatch Detection & Coverage Confidence Score**: Scans repository ASTs for reflection and dynamic invocation patterns (`getattr`, `hasattr`, `setattr`, `globals()`, `locals()`, `eval`, `exec`, `importlib.import_module`, and TypeScript bracket dispatch `obj[key]()`) and emits an explicit `AnalysisCoverageReport` (`static_parse_coverage_pct`, `unresolved_dynamic_calls_count`, `overall_blast_radius_confidence`) so CI and PR reviewers never get a false sense of security.
7. **Three Resilient Operating Modes (Supporting `gemma:latest` / Gemma 7B & `qwen2.5-coder:7b`)**:
   - **Mode A (Deterministic-only, Default)**: High-speed, 100% offline rule-based engine.
   - **Mode B (Optional Local Ollama Enhancement)**: When requested (`--llm`, `use_llm=True`, or `ATHENA_ENABLE_LLM=1`), local Ollama (`gemma:latest` / `gemma:7b` or `qwen2.5-coder:7b`) enhances narrative explanations while strictly verifying evidence citations against deterministic ground truth. Includes automatic VRAM swap eviction for 6 GB GPUs.
   - **Mode C (Fault-Tolerant Fallback)**: If Ollama times out, returns malformed JSON, or is offline, Athena gracefully degrades to deterministic output with clear diagnostic warnings.
8. **Drop-In GitHub Actions PR Audit Bot (`.github/workflows/athena-audit.yml`)**: Ships with a ready-to-use GitHub Actions workflow that runs the multi-Python test matrix and posts a structured Breaking-Change, Blast-Radius & Release Notes summary table directly to `$GITHUB_STEP_SUMMARY` on every Pull Request.
9. **Private & Accurately Annotated MCP Tools**: Athena marks analysis tools read-only. Its two release tools disclose their optional file-writing capability and write only when `output_file` is explicitly supplied; they never commit or push code. Athena runs locally on consumer hardware (verified on an NVIDIA RTX 4050 Laptop GPU with 6 GB VRAM and 16 GB RAM).

---

## Architecture

```mermaid
flowchart TD
    subgraph Client["MCP Clients & CLI"]
        CLI["Athena CLI v1.1.0\n(athena / python -m athena.cli)"]
        IDE["MCP Clients\n(Claude Desktop, Cursor, VS Code)"]
    end

    subgraph Server["Athena MCP Server (stdio)"]
        MCP["athena.mcp_server\n(7 Read-Only Annotated Tools & Schema Validation)"]
        SEC["Security & Redaction Gate\n- Path Jail & Symlink Defense\n- CLI Flag Injection Defense\n- Bearer / Key Redaction"]
    end

    subgraph Pipeline["Athena Deterministic Analysis Pipeline (Mode A)"]
        GIT["Git Inspector\n(100+ Commit Range, Partial Clone Batching, Diffs)"]
        AST["Multi-Language AST & Structural Analyzer\n- Python ast Contract & Recursion Differ\n- TS/JS/C++/C/Go/Rust/Java/C#/Ruby/PHP Scanner\n- Public API & None-Guard Analysis"]
        BLAST["Blast-Radius & Caller Engine\n(Self-Recursion, Static Import, Arity & Dynamic Call Tracing)"]
        DRIFT["Doc-Drift Scanner\n(Markdown Stale Symbol & Call-Arity Extraction)"]
        VERIFY["Evidence & Coverage Verifier\n(SHA, Line Span, Parse Coverage & Confidence)"]
    end

    subgraph OptionalAI["Optional Local LLM Enhancement (Mode B / Mode C)"]
        OLLAMA["Local Ollama Service\n(gemma:latest 7B / qwen2.5-coder:7b)"]
        FALLBACK["Graceful Degrader\n(Timeout / Malformed JSON / Offline)"]
    end

    subgraph Output["Evidence-Backed Results"]
        REPORT["Audience-Tailored Release Notes\n(Developers, Maintainers, Clients)"]
        BREAK["Potential Breaking Changes\n(Recursion Bugs, Public Exposure, Callers)"]
    end

    CLI --> SEC
    IDE --> MCP
    MCP --> SEC
    SEC --> GIT
    GIT --> AST
    AST --> BLAST
    BLAST --> DRIFT
    DRIFT --> VERIFY

    VERIFY -->|Default: Mode A| Output
    VERIFY -->|Optional --llm: Mode B| OLLAMA
    OLLAMA -->|Enhanced Output| Output
    OLLAMA -.->|Failure / Timeout| FALLBACK
    FALLBACK -->|Degraded Mode C| Output
```

---

## Installation & Setup

### Prerequisites

- **Python**: `>= 3.12` (verified on Python `3.12`, `3.13`, and `3.14`)
- **Git**: `>= 2.30` (verified on `git 2.53`)
- *(Optional)* **Ollama**: Local Ollama server at `http://127.0.0.1:11434` with `gemma:latest` (Gemma 7B, `a72c7f4d0a15`, ~5.0 GB) and/or `qwen2.5-coder:7b` (`dae161e27b0e`, ~4.7 GB) if Mode B is desired.

### Portable Installation

Clone the repository and install Athena in a clean virtual environment:

```bash
# 1. Clone repository
git clone https://github.com/aaryanrwt/athena.git
cd athena

# 2. Create and activate virtual environment
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# 3. Install in editable development mode
pip install -e .
```

---

## MCP Server Configuration

Athena communicates via standard JSON-RPC 2.0 over standard I/O (`stdio`).

### Claude Desktop (`claude_desktop_config.json`)

Add Athena to your Claude Desktop configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "athena": {
      "command": "athena",
      "args": ["mcp"],
      "env": {
        "ATHENA_ENABLE_LLM": "0"
      }
    }
  }
}
```

*Note*: To enable optional local Ollama enhancement (`gemma:latest` or `qwen2.5-coder:7b`), set `"ATHENA_ENABLE_LLM": "1"`.

### Cursor / VS Code / Other MCP Clients

For generic MCP clients using executable commands:

```json
{
  "athena": {
    "command": "python",
    "args": ["-m", "athena.cli", "mcp"]
  }
}
```

---

## Registered MCP Tools

Athena exposes **7 schema-validated MCP tools**. Five analysis tools are annotated read-only. The two release tools are annotated as write-capable because they can create or replace an explicitly requested `output_file`:

| MCP Tool Name | Primary Parameters | Description |
| :--- | :--- | :--- |
| `inspect_repository` | `repo_path` (str), `max_recent_commits` (int, default 10) | Safely inspects branch status, tags, HEAD commit, clean status, and recent commits. |
| `analyze_git_history` | `repo_path` (str), `base_ref` (str, default "AUTO"), `target_ref` (str, default "HEAD"), `max_commits` (int, default 100, up to 500), `use_llm` (bool, default False) | Extracts bounded revision range (`100+` commits), commit history, unified diffs, and multi-language AST/structural symbol deltas into grounded change stories. |
| `detect_potential_breaking_changes` | `repo_path` (str), `base_ref` (str, default "AUTO"), `target_ref` (str, default "HEAD"), `include_low_confidence` (bool, default False), `use_llm` (bool, default False) | Detects signature mutations, removed symbols, newly raised exceptions, base class changes, affected downstream callers, and documentation drift. |
| `generate_release_notes` | `repo_path` (str), `base_ref` (str, default "AUTO"), `target_ref` (str, default "HEAD"), `release_version` (str, default "Unreleased"), `audience` (str: `end_users` \| `developers` \| `maintainers` \| `clients`), `output_file` (str, optional), `overwrite` (bool, default False), `use_llm` (bool, default False) | Synthesizes audience-tailored Markdown release notes with evidence citations, upgrade considerations, and potential breaking changes. |
| `analyze_change_graph` | `repo_path` (str), `base_ref` (str), `head_ref` (str, default "HEAD"), `max_commits` (int, default 100) | Inspects deterministic symbol delta graph, caller blast radius, and commit history across `base_ref..head_ref`. |
| `verify_breaking_and_doc_drift` | `repo_path` (str), `base_ref` (str), `head_ref` (str, default "HEAD"), `include_low_confidence` (bool, default False) | Verifies breaking changes, documentation drift, and caller impact across `base_ref..head_ref`. |
| `generate_verified_release_brief` | `repo_path` (str), `base_ref` (str), `head_ref` (str, default "HEAD"), `release_version` (str), `audience` (str) | Generates structured Markdown + JSON release brief backed by verified commit and diff evidence. |

---

## CLI Usage & Verified Execution Output

The Athena CLI provides instant, zero-LLM deterministic analysis directly from your terminal. All examples below are executed directly against [`examples/demo_repo`](examples/demo_repo), a realistic Git repository with tags `v0.1.0` and `v0.2.0` (generated via `python examples/create_demo_repo.py`).

To run from source:
```bash
# 1. Generate the local demo Git repository (for testing):
python examples/create_demo_repo.py

# 2. Run Athena CLI (if installed via pip / editable):
athena <subcommand> [options]

# Or directly with Python:
python -m athena.cli <subcommand> [options]
```

### 1. Inspect Local Git Repository State

Command:
```bash
athena inspect examples/demo_repo
```

Verified Terminal Output:
```json
{
  "status": "ok",
  "repo_path": "/path/to/athena/examples/demo_repo",
  "is_valid_git_repo": true,
  "is_empty_repo": false,
  "is_shallow_repo": false,
  "current_branch": "master",
  "head_commit": {
    "commit_hash": "48e9afc3a98e8912c5a4f8ffd530f55957fbf533",
    "short_hash": "48e9afc",
    "author_name": "Athena Demo",
    "author_email": "demo@athena.local",
    "authored_date": "2026-10-17T00:02:28+05:30",
    "subject": "fix(orders): validate non-empty user_id in checkout_order",
    "changed_files": [
      "poetry.lock",
      "src/orders.py"
    ],
    "insertions": 185,
    "deletions": 3,
    "conventional_type": "fix",
    "conventional_scope": "orders",
    "declares_breaking_in_message": false
  },
  "branches": ["master"],
  "tags": ["v0.1.0", "v0.2.0"],
  "working_tree_clean": true,
  "staged_files": [],
  "unstaged_files": [],
  "untracked_files": [],
  "recent_commits": [
    {
      "commit_hash": "48e9afc3a98e8912c5a4f8ffd530f55957fbf533",
      "short_hash": "48e9afc",
      "subject": "fix(orders): validate non-empty user_id in checkout_order"
    },
    {
      "commit_hash": "0ebf335ef6880c0f93f692df5b8efd783a6a0039",
      "short_hash": "0ebf335",
      "subject": "fix: minor cleanup in billing"
    },
    {
      "commit_hash": "570fc967a42f552b003500886c7f1b7b293403f5",
      "short_hash": "570fc96",
      "subject": "feat: initial billing and order processing baseline"
    }
  ]
}
```

---

### 2. Analyze Git History & Deterministic AST Symbol Changes

Command:
```bash
athena analyze examples/demo_repo --base v0.1.0 --target v0.2.0
```

Verified Terminal Output (Excerpt):
```json
{
  "status": "ok",
  "base_ref": "v0.1.0",
  "target_ref": "v0.2.0",
  "resolved_base_sha": "570fc967a42f552b003500886c7f1b7b293403f5",
  "resolved_target_sha": "48e9afc3a98e8912c5a4f8ffd530f55957fbf533",
  "llm_backend_status": "deterministic_engine",
  "total_commits": 2,
  "total_changed_files": 3,
  "total_diff_hunks": 2,
  "stories": [
    {
      "story_id": "story_001",
      "title": "Remove `cancel_legacy_invoice` from `src/billing.py`",
      "category": "breaking_change",
      "confidence": "high",
      "observed_facts": [
        "In 'src/billing.py', symbol 'cancel_legacy_invoice' (function) underwent 'removed'.",
        "Public function 'cancel_legacy_invoice' was removed from src/billing.py.",
        "Base signature: `def cancel_legacy_invoice(invoice_id: str) -> str`",
        "Detected 1 downstream call site(s) in repository (e.g., src/orders.py:8).",
        "Detected 1 potentially stale documentation reference(s) (e.g., README.md:5)."
      ],
      "affected_files": ["src/billing.py"],
      "evidence_ids": ["ev_004", "ev_002"]
    },
    {
      "story_id": "story_002",
      "title": "Add `issue_refund` in `src/billing.py`",
      "category": "feature",
      "confidence": "high",
      "observed_facts": [
        "Introduces new public capability (`issue_refund`) in `src/billing.py`.",
        "File `src/billing.py` (modified): +12 insertions, -8 deletions.",
        "AST symbol addition confirmed in `src/billing.py` at lines 18-19."
      ],
      "affected_files": ["src/billing.py"],
      "evidence_ids": ["ev_005", "ev_002"]
    }
  ]
}
```

---

### 3. Detect Potential Breaking Changes & Caller Blast Radius

Command:
```bash
athena breaking-changes examples/demo_repo --base v0.1.0 --target v0.2.0
```

Verified Terminal Output:
```json
{
  "status": "ok",
  "total_potential_breaking_changes": 6,
  "potential_breaking_changes": [
    {
      "finding_id": "brk_001",
      "title": "Potential Breaking Change in `cancel_legacy_invoice` (removed) — Requires Human Review",
      "severity": "high",
      "confidence": "high",
      "affected_symbol": "cancel_legacy_invoice",
      "file_path": "src/billing.py",
      "change_kind": "removed",
      "old_signature": "def cancel_legacy_invoice(invoice_id: str) -> str",
      "new_signature": null,
      "observed_facts": [
        "In 'src/billing.py', symbol 'cancel_legacy_invoice' (function) underwent 'removed'.",
        "Public function 'cancel_legacy_invoice' was removed from src/billing.py.",
        "Base signature: `def cancel_legacy_invoice(invoice_id: str) -> str`",
        "Detected 1 downstream call site(s) in repository (e.g., src/orders.py:8).",
        "Detected 1 potentially stale documentation reference(s) (e.g., README.md:5)."
      ],
      "affected_callers": [
        {
          "caller_file": "src/orders.py",
          "caller_symbol": "cancel_legacy_invoice",
          "line_number": 8,
          "call_snippet": "cancel_legacy_invoice(\"inv_001\")",
          "resolution_confidence": "exact_ast"
        }
      ],
      "doc_drift": [
        {
          "doc_file": "README.md",
          "line_number": 5,
          "referenced_symbol": "cancel_legacy_invoice",
          "snippet": "`cancel_legacy_invoice(invoice_id)`",
          "drift_reason": "Documentation in 'README.md:5' references 'cancel_legacy_invoice', whose signature/availability changed (removed: Public function 'cancel_legacy_invoice' was removed from src/billing.py.).",
          "evidence_ids": ["ev_004"]
        }
      ],
      "evidence_ids": ["ev_004", "ev_002"],
      "requires_human_review": true
    },
    {
      "finding_id": "brk_003",
      "title": "Potential Breaking Change in `process_payment` (signature_changed) — Requires Human Review",
      "severity": "high",
      "confidence": "high",
      "affected_symbol": "process_payment",
      "file_path": "src/billing.py",
      "change_kind": "signature_changed",
      "old_signature": "def process_payment(user_id: str, amount_cents: int, currency: str = 'USD') -> bool",
      "new_signature": "def process_payment(user_id: str, amount_cents: int, idempotency_key: str, currency: str = 'USD') -> dict",
      "observed_facts": [
        "Added required parameter(s) ['idempotency_key'] without default values to 'process_payment'.",
        "Detected 1 downstream call site(s) in repository (e.g., src/orders.py:6)."
      ],
      "affected_callers": [
        {
          "caller_file": "src/orders.py",
          "caller_symbol": "process_payment",
          "line_number": 6,
          "call_snippet": "res = process_payment(user_id, cents, \"USD\")",
          "resolution_confidence": "exact_ast"
        }
      ],
      "evidence_ids": ["ev_006", "ev_002"],
      "requires_human_review": true
    }
  ]
}
```

---

### 4. Generate Evidence-Grounded Release Notes

Command:
```bash
athena release-notes examples/demo_repo --base v0.1.0 --target v0.2.0 --audience developers --markdown-only
```

Verified Terminal Output (Actual Markdown Rendered):
````markdown
# Release Notes — Unreleased

- **Revision Range**: `v0.1.0` (`570fc967`) -> `v0.2.0` (`48e9afc3`)
- **Target Audience**: `developers`
- **Analysis Engine**: `deterministic_engine`

## Release Summary

**Developer Technical Summary**: Release `Unreleased` (`v0.1.0` -> `v0.2.0`) spans 2 commit(s) across 3 changed file(s), synthesized into 7 evidence-backed change stories and 6 potential breaking change(s) requiring human review.

## Potential Breaking Changes (Requires Review)

- **[Requires Human Review | severity=high | confidence=high] Potential Breaking Change in `cancel_legacy_invoice` (removed) — Requires Human Review** (`def cancel_legacy_invoice(invoice_id: str) -> str` -> `removed`): Deterministic AST analysis flagged `cancel_legacy_invoice` in `src/billing.py` as a potential breaking change (Public function 'cancel_legacy_invoice' was removed from src/billing.py.). Review callers and migration notes before release. | Affected callers (1): `src/orders.py:8` | Stale docs: `README.md:5` — `0ebf335e` `src/billing.py:11-12` [ev_004], `0ebf335e` `src/billing.py:1-19` [ev_002]
- **[Requires Human Review | severity=medium | confidence=medium] Potential Breaking Change in `InvoiceStatus` (base_class_changed) — Requires Human Review** (`class InvoiceStatus(str, Enum)` -> `class InvoiceStatus(Enum)`): Deterministic AST analysis flagged `InvoiceStatus` in `src/billing.py` as a potential breaking change (Class 'InvoiceStatus' base classes changed from ['str', 'Enum'] to ['Enum'] (potential isinstance/inheritance break).). Review callers and migration notes before release. — `0ebf335e` `src/billing.py:3-5` [ev_007], `0ebf335e` `src/billing.py:1-19` [ev_002]
- **[Requires Human Review | severity=high | confidence=high] Potential Breaking Change in `process_payment` (signature_changed) — Requires Human Review** (`def process_payment(user_id: str, amount_cents: int, currency: str = 'USD') -> bool` -> `def process_payment(user_id: str, amount_cents: int, idempotency_key: str, currency: str = 'USD') -> dict`): Deterministic AST analysis flagged `process_payment` in `src/billing.py` as a potential breaking change (Added required parameter(s) ['idempotency_key'] without default values to 'process_payment'.). Review callers and migration notes before release. | Affected callers (1): `src/orders.py:6` | Stale docs: `README.md:4` — `0ebf335e` `src/billing.py:7-11` [ev_008], `0ebf335e` `src/billing.py:1-19` [ev_002]
- **[Requires Human Review | severity=medium | confidence=medium] Potential Breaking Change in `process_payment` (return_type_changed) — Requires Human Review** (`def process_payment(user_id: str, amount_cents: int, currency: str = 'USD') -> bool` -> `def process_payment(user_id: str, amount_cents: int, idempotency_key: str, currency: str = 'USD') -> dict`): Deterministic AST analysis flagged `process_payment` in `src/billing.py` as a potential breaking change (Return type annotation of 'process_payment' changed from 'bool' to 'dict'.). Review callers and migration notes before release. | Affected callers (1): `src/orders.py:6` | Stale docs: `README.md:4` — `0ebf335e` `src/billing.py:7-11` [ev_009], `0ebf335e` `src/billing.py:1-19` [ev_002]

## New Features

- **Add `issue_refund` in `src/billing.py`** (`confidence=high`): Introduces new public capability (`issue_refund`) in `src/billing.py`. Although commit message used prefix 'fix' ('fix: minor cleanup in billing'), AST diff confirms new public symbol(s) `issue_refund` were added. *(Observed: File `src/billing.py` (modified): +12 insertions, -8 deletions.)* — `0ebf335e` `src/billing.py:18-19` [ev_005], `0ebf335e` `src/billing.py:1-19` [ev_002]

## Upgrade Considerations

- **`cancel_legacy_invoice`**: Requires human review: External callers or plugins invoking the previous signature may fail at runtime with TypeError, AttributeError, or unexpected behavior.
- **`process_payment`**: Requires human review: Parameter `idempotency_key` is now required without a default.
- **Documentation Drift (`README.md:5`)**: Documentation in 'README.md:5' references 'cancel_legacy_invoice', whose signature/availability changed (removed: Public function 'cancel_legacy_invoice' was removed from src/billing.py.).
- **Documentation Drift (`README.md:4`)**: Documentation in 'README.md:4' references 'process_payment', whose signature/availability changed (signature_changed: Added required parameter(s) ['idempotency_key'] without default values to 'process_payment'.).
````

---

## Public Repository Evaluation & Benchmark Results (v1.1.0)

Athena includes an automated, reproducible evaluation harness (`tests/evaluation/run_evaluation.py`). Across its v1.0 and v1.1 evaluation suites, Athena has cloned and executed its full MCP tool suite against **140+ distinct actively maintained open-source repositories** across **11 programming languages**.

### v1.1.0 Multi-Language 100+ Commit & Dual-Model (`gemma:latest` + `qwen2.5-coder:7b`) Evaluation

For **v1.1.0**, Athena cloned and evaluated **55 brand-new, actively maintained repositories (`>= 10,000+` GitHub stars each)** spanning **11 languages** (`TypeScript`, `JavaScript`, `Python`, `C++`, `C`, `Go`, `Rust`, `Java`, `C#`, `Ruby`, `PHP`) defined in [`tests/evaluation/v1_1_multilang_manifest.json`](tests/evaluation/v1_1_multilang_manifest.json):
1. Cloned each repository into `tests/evaluation/cache` at depth `125` (`--clone-depth 125`, `--filter=blob:none`).
2. Verified reachability of at least **100 historical commits (`HEAD~100..HEAD`)** per repository.
3. Executed Athena's MCP server tools (`inspect_repository`, `analyze_git_history`, `detect_potential_breaking_changes`, and `generate_release_notes`), multi-language AST/structural signature diffing, and local Ollama `gemma:latest` + `qwen2.5-coder:7b` synthesis.

#### v1.1.0 Summary Metrics Across 55 Multi-Language Repositories (100+ Commits Each)

- **Manifest Corpus (`v1_1_multilang_manifest.json`)**: `55` actively maintained repositories (`1,558,900` cumulative GitHub stars; **55 / 55 with `>= 10,000+` stars**)
- **Languages Evaluated**: `TypeScript`, `JavaScript`, `Python`, `C++`, `C`, `Go`, `Rust`, `Java`, `C#`, `Ruby`, `PHP`
- **Repositories with `>= 100` Commits Inspected**: **`55 / 55` (`100.0%`)**
- **Passed Deep-History (`100` Commits) & 4/4 MCP Tool Suite Evaluation**: **`55 / 55` (`100.0%` pass rate)**
- **Total Commits Inspected Across v1.1.0 Corpus**: **`5,500` commits**
- **Total Diff Hunks Processed**: **`10,680` diff hunks**
- **Total Recursive Functions Analyzed (Multi-Language)**: **`411` recursive functions**
- **Average Duration per Repository (100 Commits)**: **`45.26s`**

#### Representative Multi-Language Sample from the 55 Passed v1.1.0 Repositories (`HEAD~100..HEAD`)

| Repository | Language | Stars | Range Tested | Total Commits | Inspected Commits | Diffs | Files Changed | Structural Files | Rec Fns | AST Symbols | Potential Breaks | MCP Tools | Engine / Model | Duration |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`sveltejs/svelte`** | JavaScript | 80,500 | `f2648b35..40bb0848` | 100 | 100 | 76 | 381 | 220 | 12 | 16 | 3 | 4/4 OK | `deterministic_engine` | 88.70s |
| **`gin-gonic/gin`** | Go | 79,500 | `58135f06..0f09c3a9` | 100 | 100 | 188 | 59 | 43 | 6 | 30 | 5 | 4/4 OK | `ollama:qwen2.5-coder:7b` | 54.82s |
| **`ocornut/imgui`** | C++ | 62,000 | `ed8ed8bb..4be0b47e` | 100 | 100 | 257 | 48 | 37 | 21 | 33 | 14 | 4/4 OK | `deterministic_engine` | 36.50s |
| **`scrapy/scrapy`** | Python | 53,500 | `eb744fe9..e1111a0f` | 100 | 100 | 193 | 246 | 209 | 1 | 30 | 6 | 4/4 OK | `deterministic_engine` | 58.19s |
| **`sharkdp/bat`** | Rust | 50,500 | `f1137453..f748c1a4` | 292 | 100 | 150 | 87 | 28 | 4 | 83 | 3 | 4/4 OK | `deterministic_engine` | 23.82s |
| **`BurntSushi/ripgrep`** | Rust | 50,000 | `5748f81b..3fce3b5b` | 100 | 100 | 157 | 69 | 40 | 10 | 204 | 5 | 4/4 OK | `deterministic_engine` | 24.42s |
| **`jekyll/jekyll`** | Ruby | 49,500 | `0f03b31b..97c3bdc8` | 100 | 100 | 50 | 82 | 26 | 1 | 7 | 1 | 4/4 OK | `deterministic_engine` | 13.76s |
| **`pmndrs/zustand`** | TypeScript | 49,000 | `a124d59c..d7a5583c` | 100 | 100 | 65 | 75 | 15 | 1 | 2 | 0 | 4/4 OK | `deterministic_engine` | 12.27s |
| **`ReactiveX/RxJava`** | Java | 48,000 | `c027d005..ee4a29e1` | 104 | 100 | 101 | 205 | 183 | 40 | 45 | 10 | 4/4 OK | `deterministic_engine` | 48.32s |
| **`nlohmann/json`** | C++ | 43,500 | `0c446267..4da932f5` | 100 | 100 | 1146 | 311 | 141 | 25 | 191 | 18 | 4/4 OK | `ollama:qwen2.5-coder:7b` | 64.36s |
| **`spf13/cobra`** | Go | 38,500 | `66b215ba..adbc8813` | 105 | 100 | 227 | 40 | 23 | 9 | 26 | 8 | 4/4 OK | `deterministic_engine` | 12.02s |
| **`trpc/trpc`** | TypeScript | 35,500 | `cdbc2804..1c9bf51e` | 100 | 100 | 95 | 479 | 367 | 7 | 25 | 1 | 4/4 OK | `deterministic_engine` | 64.39s |
| **`colinhacks/zod`** | TypeScript | 35,000 | `3195ed01..afdac65e` | 100 | 100 | 153 | 227 | 172 | 6 | 40 | 0 | 4/4 OK | `ollama:gemma:latest` | 84.16s |
| **`google/googletest`** | C++ | 35,000 | `a35bc769..b66cffcd` | 123 | 100 | 208 | 75 | 55 | 16 | 21 | 3 | 4/4 OK | `deterministic_engine` | 30.44s |
| **`gofiber/fiber`** | Go | 34,500 | `eb6e578f..4c6841b3` | 422 | 100 | 139 | 232 | 148 | 3 | 74 | 6 | 4/4 OK | `deterministic_engine` | 41.75s |
| **`nothings/stb`** | C | 27,500 | `7a69424f..a7d4c217` | 347 | 100 | 473 | 76 | 47 | 11 | 34 | 5 | 4/4 OK | `deterministic_engine` | 22.39s |
| **`tokio-rs/tokio`** | Rust | 27,500 | `decfd115..ce685ee6` | 270 | 100 | 87 | 268 | 248 | 16 | 44 | 1 | 4/4 OK | `deterministic_engine` | 50.95s |
| **`rollup/rollup`** | JavaScript | 25,500 | `4b6bc39e..e70c19b9` | 100 | 100 | 87 | 445 | 353 | 0 | 21 | 8 | 4/4 OK | `ollama:gemma:latest` | 89.23s |
| **`gabime/spdlog`** | C++ | 25,000 | `6fa36017..76d45805` | 100 | 100 | 128 | 151 | 137 | 2 | 16 | 6 | 4/4 OK | `deterministic_engine` | 22.64s |
| **`libuv/libuv`** | C | 24,500 | `972e78f9..bbd08cc8` | 100 | 100 | 108 | 111 | 87 | 5 | 8 | 0 | 4/4 OK | `deterministic_engine` | 32.90s |
| **`guzzle/guzzle`** | PHP | 23,300 | `7e93caca..b920e5fc` | 167 | 100 | 342 | 105 | 86 | 13 | 230 | 13 | 4/4 OK | `deterministic_engine` | 20.00s |
| **`fmtlib/fmt`** | C++ | 21,000 | `0cf9f5c9..0fc31633` | 100 | 100 | 155 | 53 | 35 | 20 | 415 | 8 | 4/4 OK | `deterministic_engine` | 25.39s |
| **`simdjson/simdjson`** | C++ | 19,500 | `edd9760b..fc358c5c` | 100 | 100 | 231 | 206 | 134 | 17 | 119 | 27 | 4/4 OK | `deterministic_engine` | 53.54s |
| **`DapperLib/Dapper`** | C# | 17,800 | `02c92d99..eb47546a` | 102 | 100 | 228 | 166 | 109 | 7 | 42 | 13 | 4/4 OK | `deterministic_engine` | 26.79s |
| **`pytest-dev/pytest`** | Python | 12,200 | `a3a62a0e..49ea4d08` | 222 | 100 | 242 | 174 | 87 | 11 | 30 | 19 | 4/4 OK | `ollama:gemma:latest` | 73.18s |
| **`DaveGamble/cJSON`** | C | 11,200 | `98ecc024..6d9f2443` | 133 | 100 | 150 | 31 | 15 | 5 | 1 | 0 | 4/4 OK | `ollama:qwen2.5-coder:7b` | 41.32s |
| **`lz4/lz4`** | C | 10,600 | `9da37b2e..1deef0b7` | 272 | 100 | 267 | 70 | 31 | 23 | 60 | 9 | 4/4 OK | `deterministic_engine` | 29.12s |
| **`serde-rs/serde`** | Rust | 10,100 | `e3eaa6a3..0db9b3b5` | 208 | 100 | 153 | 103 | 68 | 1 | 40 | 8 | 4/4 OK | `deterministic_engine` | 35.69s |

*Complete 55-repository v1.1.0 report is preserved in [`tests/evaluation/results/EVALUATION_REPORT.md`](tests/evaluation/results/EVALUATION_REPORT.md) and machine-readable data in [`tests/evaluation/results/evaluation_results.json`](tests/evaluation/results/evaluation_results.json). Additionally, Athena's initial 85-repository 50-commit evaluation (`4,398,500+` cumulative stars across `facebook/react`, `microsoft/vscode`, `huggingface/transformers`, `vercel/next.js`, `golang/go`, `ollama/ollama`, `nodejs/node`, `pytorch/pytorch`, `django/django`, `tiangolo/fastapi`, etc.) achieved a 98.8% pass rate on reachable 50+ commit histories.*

---

### Ground-Truth Semantic Quality Benchmark (19 Scenarios — 100.0% Pass Rate)

Athena was rigorously evaluated against a dedicated 19-scenario ground-truth contract & recursion mutation benchmark (`tests/evaluation/run_quality_benchmark.py`). **19 / 19 scenarios passed (100.0% accuracy)** across Mode A (Deterministic) and Mode B (both `ollama:qwen2.5-coder:7b` and `ollama:gemma:latest`):

| Scenario ID | Test Scenario | Ground Truth Contract Change | Mode A & B Detection | Pass / Fail | Evidence / Observed Facts |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`SCENARIO-01`** | **Function Rename** | `calculate_tax` renamed to `compute_tax` | Flagged as removed public symbol | **PASS** | `calculate_tax` flagged (`severity=high`) |
| **`SCENARIO-02`** | **Added Required Parameter** | Added `timeout: int` without default | Flagged as breaking signature mutation | **PASS** | Exact parameter diff tracked |
| **`SCENARIO-03`** | **Parameter Removed** | Removed `timeout: int` without kwargs | Flagged as breaking signature mutation | **PASS** | Parameter removal identified |
| **`SCENARIO-04`** | **Added Optional Parameter** | Added `limit: int = 100` with default | Exempted as backward-compatible | **PASS** | `is_breaking_candidate=False` |
| **`SCENARIO-05`** | **Unguarded `default=None`** | Default changed to `None` without guard | Flagged as breaking (`TypeError` risk) | **PASS** | Body AST verified lack of guard |
| **`SCENARIO-06`** | **Guarded `default=None`** | Default changed to `None` with `if val is None:` | Exempted as non-breaking (`griffe#469`) | **PASS** | Body fallback guard detected |
| **`SCENARIO-07`** | **Return Type Changed** | Return annotation `int -> str` | Flagged as return type mutation | **PASS** | Type annotation diff verified |
| **`SCENARIO-08`** | **Newly Raised Exception** | Function now raises `ValueError` | Flagged as new exception path (`griffe#498`) | **PASS** | AST raise node detected |
| **`SCENARIO-09`** | **Base Class Mutation** | Base class added required method parameter | Flagged as inheritance contract break | **PASS** | Subclass override risk flagged |
| **`SCENARIO-10`** | **Harmless Refactor** | Local body rewrite with identical signature | Zero breaking changes reported | **PASS** | 0 false positives |
| **`SCENARIO-11`** | **Caller Blast Radius** | Cross-file function signature mutation | Call sites mapped in `caller_a.py` & `caller_b.py` | **PASS** | Downstream file & line spans traced |
| **`SCENARIO-12`** | **Lockfile & Doc Drift** | Bumps `poetry.lock` + stale `:param:` docstring | Lockfile ignored; phantom parameter flagged | **PASS** | Doc drift flagged, 0 false API breaks |
| **`SCENARIO-13`** | **Public API Exposure Flag** | `__all__` / `__init__.py` export vs `_private.py` | `is_public_api_export=True` vs `False` | **PASS** | External consumer risk differentiated |
| **`SCENARIO-14`** | **Dynamic Call & Coverage** | `getattr`, `importlib`, `globals()` dispatch | 3 unresolved dynamic calls flagged; confidence=`medium` | **PASS** | Coverage `100.0%`, dynamic blindspots surfaced |
| **`SCENARIO-15`** | **`StrEnum` & Enum Members** | `(str, Enum)` -> `StrEnum` (`griffe#501`) + removed member | Both base semantic break & removed member flagged | **PASS** | Enum member & formatting contract verified |
| **`SCENARIO-16`** | **`.gitconfig` & `qwen2.5-coder:7b`** | `diff.noprefix=true` + stale README call + `qwen2.5-coder:7b` | Mode A & Mode B (`ollama:qwen2.5-coder:7b`) both pass | **PASS** | `.gitconfig` spoofing immune + doc arity drift caught |
| **`SCENARIO-17`** | **Recursive Function Arity Break** | Recursive function adds required param, omits in self-call | Flagged in breaking findings & `affected_callers` (`BUG-021`) | **PASS** | Self-recursive call arity mismatch caught |
| **`SCENARIO-18`** | **Infinite Recursion & Method Call** | Missing base case & unqualified `step()` in class method | Flagged `RecursionError` & `NameError` defects (`BUG-022`) | **PASS** | AST control-flow & method scope verified |
| **`SCENARIO-19`** | **Ollama `gemma:latest` (Gemma 7B)** | Hybrid recursive diff synthesis with `gemma:7b` alias | `ollama:gemma:latest` verified with 0 warnings (`BUG-025`) | **PASS** | Verified against `ev_001` & `src/recursion.py` |

*Complete benchmark report is documented in [`tests/evaluation/results/QUALITY_BENCHMARK_REPORT.md`](tests/evaluation/results/QUALITY_BENCHMARK_REPORT.md).*

---

### Engineering Defect Reports

- **Bug Reports (BUG-001 through BUG-039)**: Full root-cause analysis and resolution records for **39 isolated engineering defects** (including evaluation depth, Windows process tree termination, packfile permission locks, metric conflation, unguarded parameter fallbacks, SemVer `+` build metadata, NTFS Alternate Data Stream injection, Windows reserved device names, positional-only parameter markers, `@staticmethod` argument preservation, `@property` getter/setter coexistence, TypeScript generic functions, aliased imports, `.gitconfig` `diff.noprefix` spoofing immunity, historical Git blob caller lookup, Markdown call-arity drift in modified docs, `StrEnum` migration & Enum member diffing, body-only function mutation test-gap tracking, pre-filter coverage calculation on multi-language repos, self-recursive caller blindspot & broken recursive arity (`BUG-021`), unconditional infinite recursion & unqualified method self-calls (`BUG-022`), deep AST `RecursionError` hardening (`BUG-023`), multi-class method short-name collision (`BUG-024`), local Ollama `gemma:latest` 7B VRAM swap eviction & JSON normalization (`BUG-025`), MCP tool error boundaries & `bool`-as-`int` validation (`BUG-026`), `pytest` cache recursion isolation (`BUG-027`), partial-clone `--numstat` / `-M` lazy network fetch timeouts (`BUG-028`), redundant `HEAD` blob subprocess storms (`BUG-029`), optional parameter insertion before positional parameters (`BUG-030`), alphabetical doc/test AST blob starvation (`BUG-031`), cross-header `#include` relocation & asymmetric blob guards (`BUG-032`), $O(\text{files} \times \text{symbols} \times \text{lines})$ caller regex compilation speedup (`BUG-033`), C++ namespace indentation & Ruby `def self.foo` collisions (`BUG-034`), multi-language recursive function & broken self-call arity detection (`BUG-035`), `gemma:latest` token truncation on long monorepo paths (`BUG-036`), delegated `$obj->method()` & `parent::method()` recursion immunity (`BUG-037`), C++ `return call("lit");` statement immunity (`BUG-038`), and multi-language test file detection (`BUG-039`)) are cataloged in [`tests/evaluation/results/BUG_REPORTS.md`](tests/evaluation/results/BUG_REPORTS.md).

---

## Tested Security Controls & Boundaries

- **Path Canonicalization & Jail**: All filesystem paths are resolved and validated with `is_relative_to(repo_root)`. Path traversal attempts (e.g. `../../etc/passwd` or symlink escapes) are blocked with `INVALID_REPO_PATH`.
- **Windows Device Name & ADS Guards**: Output file paths are verified against Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) and NTFS Alternate Data Stream colons (`:`) to prevent device locks and stream injection.
- **CLI Flag Injection & `.gitconfig` Spoofing Neutralization**: Revisions and arguments passed to Git subprocesses are validated to prevent flag injection attacks (blocking leading `-`, `--upload-pack`, `-o`, `--exec`), and all Git commands enforce `-c diff.noprefix=false -c diff.mnemonicPrefix=false -c color.ui=never`.
- **Safe File Writing**: Release-note writing requires explicit `overwrite=True` to prevent destructive overwriting of existing changelogs.
- **Pre-LLM Secret Redaction**: High-entropy strings, AWS tokens (`AKIA...`), GitHub personal access tokens (`ghp_...`), Bearer headers, and private keys are redacted prior to LLM or markdown exposure.
- **Prompt Injection Isolation**: Repository content forwarded to optional LLMs is strictly fenced inside `<untrusted_repo_content>` XML tags with explicit system instructions to ignore embedded directives.

---

## Current Scope & Limitations

- **Language AST & Structural Support**: Full AST contract and recursion defect analysis (parameter defaults, body guards, return types, exception raises, base classes, Enum members, public constants, recursive self-call arity, and infinite recursion base-case detection) is implemented for **Python**. Multi-language structural symbol, signature, parameter arity, visibility, export diffing, and recursive self-call arity analysis is supported for **TypeScript, JavaScript, C++, C, Go, Rust, Java, Kotlin, Scala, C#, Ruby, PHP, and Swift**.
- **Inter-file Caller Resolution & Dynamic Dispatch**: Static caller analysis resolves callers across local modules within the same repository using import hierarchy tracking (including aliased imports and self-recursive calls) and verifies call-site argument arity. When reflection (`getattr`), dynamic imports (`importlib.import_module`), or bracket dispatch (`handlers[action]()`) are present, Athena explicitly flags them in `unresolved_dynamic_calls` and adjusts `analysis_coverage.overall_blast_radius_confidence` so reviewers know the exact boundary of static analysis.
- **Read-Only Operation**: Athena does not write tags, create branches, or commit code to external repositories.
- **Partial/Blobless Clones**: Athena disables implicit Git lazy-fetching during analysis. A partial clone must already contain the objects required for the requested range; otherwise Athena returns a Git extraction error instead of contacting its remote without explicit operator action.

---

## Running the Automated Test Suite

Athena has **128 tests** covering multi-language structural and recursive diffing, security boundaries, MCP stdio roundtrips, and real-world edge cases. The default offline run executes 127 tests and skips one explicitly opt-in live Ollama integration test:

```bash
# Run the offline suite (127 passed, 1 live Ollama test skipped)
python -m pytest -v

# Optional live Ollama test (Linux/macOS)
ATHENA_RUN_OLLAMA_TESTS=1 python -m pytest -v -m ollama

# Optional live Ollama test (Windows PowerShell)
$env:ATHENA_RUN_OLLAMA_TESTS = "1"; python -m pytest -v -m ollama

# Run 19-scenario ground-truth semantic quality & Gemma 7B / Qwen 7B benchmark
python tests/evaluation/run_quality_benchmark.py

# Run v1.1.0 multi-language 100+ commit & MCP repository evaluation (55 repos, 10k+ stars)
python tests/evaluation/run_evaluation.py --manifest tests/evaluation/v1_1_multilang_manifest.json --limit 55 --clone-depth 125 --target-commits 100 --llm --model dual
```

---

## Owner & Maintainer

- **Name**: Aaryan Rawat
- **Email**: [`aaryan28rwt@gmail.com`](mailto:aaryan28rwt@gmail.com)
- **GitHub**: [@aaryanrwt](https://github.com/aaryanrwt)
- **Project history**: [`CHANGELOG.md`](CHANGELOG.md)
- **Maintainer feedback and follow-up**: [`MAINTAINER_FEEDBACK.md`](MAINTAINER_FEEDBACK.md)

---

## License

Athena is licensed under the [Apache License, Version 2.0](LICENSE).
