## CLI Usage & Verified Execution Output

The Athena CLI provides instant, zero-LLM deterministic analysis directly from your terminal. All examples below are executed directly against [`examples/demo_repo`](../examples/demo_repo), a realistic Git repository with tags `v0.1.0` and `v0.2.0` (generated via `python examples/create_demo_repo.py`).

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

### 5. Launch Interactive Studio Terminal UI

Command:
```bash
athena ui
```

Launches the interactive Athena Studio TUI with retro modular block typography, terracotta color palette, live repository context card (branch, staged/unstaged files, HEAD commit), and one-click numeric action shortcuts (`[1-8, q]`).

### 6. Pre-Commit Staged Breaking-Change Gate

Command:
```bash
athena check --staged
```

Analyzes git staged index changes against HEAD deterministically. If breaking API mutations are staged, exits non-zero (`1`) and prints actionable warnings without altering files or git refs.

### 7. Automated SemVer Bump Check

Command:
```bash
athena semver-check . --declared patch
```

Analyzes breaking changes in the repository against the declared version bump (`patch`, `minor`, `major`). Fails with non-zero exit if breaking changes require a higher bump than declared.

### 8. Generate Standalone HTML Report

Command:
```bash
athena report . --html --output athena-report.html
```

Renders a self-contained, offline HTML report featuring visual call graphs, affected callers, and unified diff excerpts with zero external assets or scripts.

### 9. One-Click MCP Client Configuration

Command:
```bash
# Print ready-to-use configuration JSON to stdout:
athena init-mcp cursor
athena init-mcp claude-desktop
athena init-mcp vscode

# Or write directly to configuration file safely:
athena init-mcp cursor --write --path .cursor/mcp.json
```

Prints or safely writes configuration JSON for Cursor, Claude Desktop, or VS Code. Never overwrites existing files without `--force`.

### 10. Export Breaking Changes in SARIF 2.1.0 for CI & Code Scanning

Command:
```bash
athena breaking-changes . --base main --target HEAD --format sarif
```

Formats AST breaking change findings, affected symbols, and line spans into standard Static Analysis Results Interchange Format (SARIF 2.1.0) for GitHub Code Scanning, SonarQube, and IDE security viewers.

### 11. Incremental Content-Hash Symbol Cache

Command:
```bash
athena --cache-dir .athena-cache breaking-changes . --base main --target HEAD
```

Enables opt-in SHA-256 content-hash caching for parsed symbols across large repositories. Can also be enabled globally via the `ATHENA_CACHE_DIR` environment variable.
