# Contributing to Athena (`athena-mcp`)

Thank you for your interest in contributing to **Athena** — our local-first, evidence-backed Git & AST change-intelligence MCP server!

Whether you are reporting an AST edge case, improving caller blast-radius precision, adding language support, or fixing documentation drift, your contributions are welcome.

---

## Development Setup

### Prerequisites
- **Python**: `>= 3.12` (verified on Python `3.12`, `3.13`, and `3.14`)
- **Git**: `>= 2.30`
- *(Optional)* **Ollama**: Local Ollama server at `http://127.0.0.1:11434` (`gemma:latest` / `gemma:7b` or `qwen2.5-coder:7b`) for Mode B tests.

### Clone & Install

```bash
git clone https://github.com/aaryanrwt/athena.git
cd athena
python -m venv .venv

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate

pip install -e ".[dev]"
```

---

## Running the Test Suite

Always run the deterministic test suite before opening a Pull Request:

```bash
# Run the default offline unit, protocol, and real-world AST/Git suite
python -m pytest -v -m "not ollama"

# Opt in to the live local Ollama integration test
# Linux/macOS: ATHENA_RUN_OLLAMA_TESTS=1 python -m pytest -v -m ollama
# PowerShell: $env:ATHENA_RUN_OLLAMA_TESTS = "1"; python -m pytest -v -m ollama

# Run the 19-scenario precision/recall quality benchmark
python tests/evaluation/run_quality_benchmark.py
```

---

## Core Design Principles

When contributing changes to `src/athena/`, please preserve Athena's core invariants:

1. **Deterministic-First (Mode A)**: Every analysis feature must work 100% offline with 0ms LLM dependency. Local Ollama enhancement (Mode B) is strictly optional and must gracefully fall back to deterministic output (Mode C) on timeout or malformed JSON.
2. **Ground-Truth Evidence**: Every reported `ChangeStory` and `BreakingChangeFinding` must attach verified `EvidenceRecord` citations (40-char commit SHA, file path, exact base/target line spans, and diff hunk excerpt).
3. **Sandbox-Safe**: Analysis must never mutate the target repository or execute repository code. Release tools may write only to an explicitly requested, validated output path and must disclose that capability through MCP annotations.
4. **Regression Test Coverage**: Every bug fix or new AST contract rule should include a deterministic regression test in `tests/test_real_world_edge_cases.py`.

---

## Pull Request Process

1. Fork the repository and create a feature or bugfix branch from `main` (e.g. `fix/ast-kwonly-defaults` or `feat/rust-contract-scanner`).
2. Add or update unit/regression tests in `tests/` covering your change.
3. Ensure `python -m pytest` passes with zero failures.
4. Open a Pull Request clearly describing:
   - The problem or edge case (with a minimal before/after code reproduction if applicable).
   - How the fix or feature works.
   - Verification steps and test output.

By contributing to Athena, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).

---

## Maintainer & Owner

- **Aaryan Rawat** — [aaryan28rwt@gmail.com](mailto:aaryan28rwt@gmail.com) ([`@aaryanrwt`](https://github.com/aaryanrwt))
