"""Comprehensive Automated Test Suite for Athena MVP (14 Required Scenarios + Live qwen2.5-coder:7b Integration)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from athena.mcp_server import (
    analyze_git_history,
    detect_potential_breaking_changes,
    generate_release_notes,
    inspect_repository,
)
from athena.models import LogicalChangeStory
from athena.ollama_engine import check_ollama_model_ready
from athena.release_notes import (
    run_breaking_change_detection,
    run_git_history_analysis,
    run_release_notes_generation,
)
from athena.security import redact_secrets, validate_git_revision
from athena.verifier import verify_and_hydrate_stories


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


@pytest.fixture()
def sample_git_repo(tmp_path: Path) -> Path:
    """Create a realistic multi-commit Git repository with tags, Python & TS code, callers, tests, and docs."""
    repo = tmp_path / "Sample Windows Repo"
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init")
    _git(repo, "config", "user.name", "Athena Tester")
    _git(repo, "config", "user.email", "tester@example.com")

    # Commit 1 (v0.1.0): Initial baseline
    (repo / "src").mkdir()
    (repo / "tests").mkdir()
    (repo / "src" / "payments.py").write_text(
        'from enum import Enum\n\n'
        'class Currency(str, Enum):\n'
        '    USD = "USD"\n'
        '    EUR = "EUR"\n\n'
        '@classmethod\n'
        'def charge_card(amount: int, currency: str = "USD") -> bool:\n'
        '    """Charge a customer card."""\n'
        '    return amount > 0\n\n'
        'def legacy_refund(tx_id: str) -> str:\n'
        '    return f"refunded:{tx_id}"\n\n'
        'def connect_gateway(timeout: int = 30) -> str:\n'
        '    return f"connected:{timeout}"\n',
        encoding="utf-8",
    )
    (repo / "src" / "checkout.py").write_text(
        'from src.payments import charge_card, legacy_refund\n\n'
        'def run_checkout(total: int) -> bool:\n'
        '    ok = charge_card(total, "USD")\n'
        '    legacy_refund("tx_100")\n'
        '    return ok\n',
        encoding="utf-8",
    )
    (repo / "src" / "client.ts").write_text(
        'export function fetchInvoice(invoiceId: string): string {\n'
        '    return invoiceId;\n'
        '}\n',
        encoding="utf-8",
    )
    (repo / "README.md").write_text(
        '# Sample Payments Service\n\n'
        'Usage example:\n'
        '```python\n'
        'charge_card(100, "USD")\n'
        'legacy_refund("tx_123")\n'
        '```\n',
        encoding="utf-8",
    )
    (repo / "tests" / "test_payments.py").write_text(
        'from src.payments import connect_gateway\n\n'
        'def test_connect():\n'
        '    assert "connected" in connect_gateway()\n',
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat: initial payments and checkout baseline")
    _git(repo, "tag", "v0.1.0")

    # Commit 2: Misleading commit message ("fix: minor tweak") that actually introduces:
    # - Breaking signature change on charge_card (adds required param `merchant_id`, changes return type to dict, removes @classmethod, raises ValueError)
    # - Removes public function `legacy_refund`
    # - Changes `connect_gateway(timeout: int | None = None)` WITH an `if timeout is None:` body guard (griffe#469 non-breaking pattern!)
    # - Adds new public function `create_subscription(plan_id: str) -> str`
    # - Changes Currency base class from (str, Enum) to (Enum) (griffe#501)
    (repo / "src" / "payments.py").write_text(
        'from enum import Enum\n\n'
        'class Currency(Enum):\n'
        '    USD = "USD"\n'
        '    EUR = "EUR"\n\n'
        'def charge_card(amount: int, merchant_id: str, currency: str = "USD") -> dict:\n'
        '    """Charge a customer card with mandatory merchant_id."""\n'
        '    if amount <= 0:\n'
        '        raise ValueError("Invalid amount")\n'
        '    return {"ok": True, "merchant": merchant_id, "currency": currency}\n\n'
        'def connect_gateway(timeout: int | None = None) -> str:\n'
        '    if timeout is None:\n'
        '        timeout = 30\n'
        '    return f"connected:{timeout}"\n\n'
        'def create_subscription(plan_id: str) -> str:\n'
        '    return f"sub:{plan_id}"\n',
        encoding="utf-8",
    )
    # Also modify TypeScript export signature incompatibly (add required `region: string`)
    (repo / "src" / "client.ts").write_text(
        'export function fetchInvoice(invoiceId: string, region: string): string {\n'
        '    return `${region}:${invoiceId}`;\n'
        '}\n',
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "fix: minor tweak to payment helpers")

    # Commit 3 (v0.2.0): Lockfile + bugfix with validation guard
    (repo / "package-lock.json").write_text('{"name": "lockfile", "lockfileVersion": 3}\n' * 100, encoding="utf-8")
    (repo / "src" / "checkout.py").write_text(
        'from src.payments import charge_card, legacy_refund\n\n'
        'def run_checkout(total: int) -> bool:\n'
        '    if not isinstance(total, int):\n'
        '        raise TypeError("total must be int")\n'
        '    res = charge_card(total, "USD")\n'
        '    legacy_refund("tx_100")\n'
        '    return bool(res)\n',
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "fix(checkout): validate total integer type in run_checkout")
    _git(repo, "tag", "v0.2.0")

    return repo


def test_1_valid_local_git_repository_and_windows_paths(sample_git_repo: Path) -> None:
    """Scenario 1 & 13: Valid local Git repository on Windows path with spaces."""
    res = inspect_repository(str(sample_git_repo), max_recent_commits=5)
    assert res["status"] == "ok"
    assert res["is_valid_git_repo"] is True
    assert res["is_empty_repo"] is False
    assert "v0.1.0" in res["tags"]
    assert "v0.2.0" in res["tags"]
    assert len(res["recent_commits"]) == 3
    assert res["working_tree_clean"] is True


def test_2_invalid_repository_paths(tmp_path: Path) -> None:
    """Scenario 2: Non-existent path, file path instead of directory, and non-Git directory."""
    missing = inspect_repository(str(tmp_path / "does_not_exist_12345"))
    assert missing["status"] == "error"
    assert missing["error_code"] == "REPO_PATH_NOT_FOUND"

    regular_file = tmp_path / "some_file.txt"
    regular_file.write_text("hello", encoding="utf-8")
    not_dir = inspect_repository(str(regular_file))
    assert not_dir["status"] == "error"
    assert not_dir["error_code"] == "REPO_PATH_NOT_DIRECTORY"

    plain_dir = tmp_path / "plain_folder"
    plain_dir.mkdir()
    not_git = inspect_repository(str(plain_dir))
    assert not_git["status"] == "error"
    assert not_git["error_code"] == "NOT_A_GIT_REPOSITORY"


def test_3_invalid_revisions_and_flag_injection_blocking(sample_git_repo: Path) -> None:
    """Scenario 3: Invalid revision/tag range and CVE-2025-68144 Git argument injection protection."""
    bad_rev = analyze_git_history(str(sample_git_repo), base_ref="v9.9.9-nonexistent", target_ref="HEAD", use_llm=False)
    assert bad_rev["status"] == "error"
    assert bad_rev["error_code"] == "REVISION_NOT_FOUND"

    flag_inj = analyze_git_history(str(sample_git_repo), base_ref="--output=/tmp/exploit", target_ref="HEAD", use_llm=False)
    assert flag_inj["status"] == "error"
    assert flag_inj["error_code"] == "GIT_FLAG_INJECTION_BLOCKED"

    bad_base_wt = analyze_git_history(str(sample_git_repo), base_ref="WORKING_TREE", target_ref="HEAD", use_llm=False)
    assert bad_base_wt["status"] == "error"
    assert bad_base_wt["error_code"] == "INVALID_BASE_REVISION"


def test_4_empty_diff_between_identical_revisions(sample_git_repo: Path) -> None:
    """Scenario 4: Empty diff between identical revisions."""
    res = analyze_git_history(str(sample_git_repo), base_ref="v0.1.0", target_ref="v0.1.0", use_llm=False)
    assert res["status"] == "ok"
    assert res["total_commits"] == 0
    assert res["total_changed_files"] == 0
    assert res["stories"] == []
    assert res["llm_backend_status"] == "skipped_empty_diff"


def test_5_empty_repository_and_repository_without_tags(tmp_path: Path) -> None:
    """Scenario 5: Empty repository (no commits) and repository with commits but no tags."""
    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()
    _git(empty_repo, "init")

    insp = inspect_repository(str(empty_repo))
    assert insp["status"] == "ok"
    assert insp["is_valid_git_repo"] is True
    assert insp["is_empty_repo"] is True
    assert insp["recent_commits"] == []

    hist_empty = analyze_git_history(str(empty_repo), base_ref="HEAD", target_ref="HEAD", use_llm=False)
    assert hist_empty["status"] == "error"
    assert hist_empty["error_code"] == "EMPTY_REPOSITORY"

    # Repo without tags: AUTO base_ref resolves to root commit
    notag_repo = tmp_path / "notag_repo"
    notag_repo.mkdir()
    _git(notag_repo, "init")
    _git(notag_repo, "config", "user.name", "Tester")
    _git(notag_repo, "config", "user.email", "tester@example.com")
    (notag_repo / "app.py").write_text("def hello() -> str:\n    return 'v1'\n", encoding="utf-8")
    _git(notag_repo, "add", ".")
    _git(notag_repo, "commit", "-m", "initial commit")
    (notag_repo / "app.py").write_text("def hello(name: str) -> str:\n    return f'hi {name}'\n", encoding="utf-8")
    _git(notag_repo, "add", ".")
    _git(notag_repo, "commit", "-m", "feat: require name in hello")

    hist_notag = analyze_git_history(str(notag_repo), base_ref="AUTO", target_ref="HEAD", use_llm=False)
    assert hist_notag["status"] == "ok"
    assert hist_notag["total_commits"] == 1
    assert hist_notag["total_changed_files"] == 1


def test_6_large_diff_and_lockfile_exclusion(sample_git_repo: Path) -> None:
    """Scenario 6: Lockfiles are marked skipped_large_or_lockfile and excluded from deep diffing."""
    res = analyze_git_history(str(sample_git_repo), base_ref="v0.1.0", target_ref="v0.2.0", use_llm=False)
    assert res["status"] == "ok"
    files_by_path = {f["file_path"]: f for f in res["changed_files"]}
    assert "package-lock.json" in files_by_path
    assert files_by_path["package-lock.json"]["status"] == "skipped_large_or_lockfile"
    assert files_by_path["package-lock.json"]["bounded_diff"] == ""


def test_7_ollama_unavailable_graceful_fallback(sample_git_repo: Path) -> None:
    """Scenario 7: When Ollama is unreachable, Athena falls back deterministically without crashing."""
    report = run_git_history_analysis(
        repo_path=sample_git_repo,
        base_ref="v0.1.0",
        target_ref="v0.2.0",
        use_llm=True,
        ollama_url="http://127.0.0.1:59999",  # Unreachable port
        timeout_seconds=1.5,
    )
    assert report.status == "ok"
    assert report.llm_backend_status == "fallback_deterministic"
    assert any("Ollama unavailable" in w for w in report.warnings)
    assert len(report.stories) >= 2


def test_8_model_timeout_malformed_json_and_hallucination_stripping(sample_git_repo: Path) -> None:
    """Scenario 8 & 10: Model timeout, malformed JSON response, and verifier stripping hallucinated evidence."""
    with patch("athena.ollama_engine.check_ollama_model_ready", return_value=(True, None)):
        with patch("athena.ollama_engine.httpx.post", side_effect=httpx.ReadTimeout("Simulated VRAM timeout")):
            rep_timeout = run_git_history_analysis(
                repo_path=sample_git_repo,
                base_ref="v0.1.0",
                target_ref="v0.2.0",
                use_llm=True,
            )
            assert rep_timeout.status == "ok"
            assert rep_timeout.llm_backend_status == "fallback_deterministic"
            assert any("timed out" in w or "ReadTimeout" in w for w in rep_timeout.warnings)

        with patch(
            "athena.ollama_engine.httpx.post",
            side_effect=RuntimeError(
                "request to https://athena-user:synthetic-password-123@ollama.internal failed"
            ),
        ):
            rep_credential_error = run_git_history_analysis(
                repo_path=sample_git_repo,
                base_ref="v0.1.0",
                target_ref="v0.2.0",
                use_llm=True,
            )
            warnings = "\n".join(rep_credential_error.warnings)
            assert "synthetic-password-123" not in warnings
            assert "[REDACTED_URI_CREDENTIAL]" in warnings

        mock_malformed = MagicMock()
        mock_malformed.status_code = 200
        mock_malformed.json.return_value = {"response": "NOT_JSON {{{{ broken output"}
        with patch("athena.ollama_engine.httpx.post", return_value=mock_malformed):
            rep_malformed = run_git_history_analysis(
                repo_path=sample_git_repo,
                base_ref="v0.1.0",
                target_ref="v0.2.0",
                use_llm=True,
            )
            assert rep_malformed.status == "ok"
            assert rep_malformed.llm_backend_status == "fallback_deterministic"
            assert any("not valid JSON" in w for w in rep_malformed.warnings)

        # Test hallucinated story & fake evidence_id stripping
        mock_hallucinated = MagicMock()
        mock_hallucinated.status_code = 200
        mock_hallucinated.json.return_value = {
            "response": (
                '{"stories": ['
                '{"story_id": "s_fake", "title": "Hallucinated Quantum Module", "category": "feature", '
                '"confidence": "high", "uncertainty_notes": "none", "observed_facts": ["fake"], '
                '"model_interpretation": "fake", "potential_risks_requiring_verification": [], '
                '"affected_files": ["src/quantum_nonexistent.py"], "commit_hashes": ["deadbeef9999"], '
                '"evidence_ids": ["ev_999_hallucinated"]},'
                '{"story_id": "s_real", "title": "Valid Payment Update", "category": "feature", '
                '"confidence": "high", "uncertainty_notes": "none", "observed_facts": ["Updated payments.py"], '
                '"model_interpretation": "Added create_subscription", "potential_risks_requiring_verification": [], '
                '"affected_files": ["src/payments.py"], "commit_hashes": [], '
                '"evidence_ids": ["ev_999_fake", "ev_001"]}'
                ']}'
            )
        }
        with patch("athena.ollama_engine.httpx.post", return_value=mock_hallucinated):
            rep_filtered = run_git_history_analysis(
                repo_path=sample_git_repo,
                base_ref="v0.1.0",
                target_ref="v0.2.0",
                use_llm=True,
            )
            assert rep_filtered.status == "ok"
            assert rep_filtered.stripped_ungrounded_claims_count >= 3
            titles = [s.title for s in rep_filtered.stories]
            assert "Hallucinated Quantum Module" not in titles
            assert "Valid Payment Update" in titles


def test_9_release_notes_generation_audiences_and_safe_file_writing(sample_git_repo: Path) -> None:
    """Scenario 9: Release notes generation, audience tailoring, misleading commit detection, and overwrite guard."""
    out_rel = "docs/RELEASE_v0.2.0.md"
    res = generate_release_notes(
        repo_path=str(sample_git_repo),
        base_ref="v0.1.0",
        target_ref="v0.2.0",
        release_version="v0.2.0",
        audience="maintainers",
        output_file=out_rel,
        overwrite=False,
        use_llm=False,
    )
    assert res["status"] == "ok"
    assert res["saved_to_file"] is not None
    saved_file = Path(res["saved_to_file"])
    assert saved_file.exists()
    md = res["markdown"]
    assert "# Release Notes — v0.2.0" in md
    assert "## Potential Breaking Changes (Requires Review)" in md
    assert "## New Features" in md
    assert "create_subscription" in md
    assert "## Upgrade Considerations" in md

    # Attempting to write again with overwrite=False must fail safely without clobbering
    res_denied = generate_release_notes(
        repo_path=str(sample_git_repo),
        base_ref="v0.1.0",
        target_ref="v0.2.0",
        release_version="v0.2.0",
        audience="end_users",
        output_file=out_rel,
        overwrite=False,
        use_llm=False,
    )
    assert res_denied["status"] == "error"
    assert res_denied["error_code"] == "FILE_EXISTS_OVERWRITE_DENIED"

    # With overwrite=True, succeeds
    res_overwrite = generate_release_notes(
        repo_path=str(sample_git_repo),
        base_ref="v0.1.0",
        target_ref="v0.2.0",
        release_version="v0.2.0",
        audience="end_users",
        output_file=out_rel,
        overwrite=True,
        use_llm=False,
    )
    assert res_overwrite["status"] == "ok"

    # Clean up generated release notes file so repo stays clean
    saved_file.unlink(missing_ok=True)

    # Path traversal outside repo must be blocked
    res_escape = generate_release_notes(
        repo_path=str(sample_git_repo),
        base_ref="v0.1.0",
        target_ref="v0.2.0",
        output_file="../escaped_notes.md",
        overwrite=True,
        use_llm=False,
    )
    assert res_escape["status"] == "error"
    assert res_escape["error_code"] == "OUTPUT_PATH_ESCAPE_BLOCKED"


def test_10_mode_a_pure_deterministic_offline_zero_network(sample_git_repo: Path) -> None:
    """Scenario 10: Mode A Deterministic-only execution works 100% offline with zero network/LLM dependencies."""
    # Patch httpx to ensure no HTTP connection or external service is contacted
    with patch("athena.ollama_engine.httpx.post", side_effect=RuntimeError("Network forbidden in Mode A")), \
         patch("athena.ollama_engine.httpx.get", side_effect=RuntimeError("Network forbidden in Mode A")):
        
        # 1. Git history analysis
        hist = run_git_history_analysis(
            repo_path=sample_git_repo,
            base_ref="v0.1.0",
            target_ref="v0.2.0",
            use_llm=False,
        )
        assert hist.status == "ok"
        assert hist.llm_backend_status == "deterministic_engine"
        assert hist.warnings == []
        assert len(hist.stories) >= 2
        assert len(hist.evidence_registry) >= 4

        # 2. Release notes generation
        rel = run_release_notes_generation(
            repo_path=sample_git_repo,
            base_ref="v0.1.0",
            target_ref="v0.2.0",
            audience="developers",
            use_llm=False,
        )
        assert rel.status == "ok"
        assert rel.llm_backend_status == "deterministic_engine"
        assert rel.warnings == []
        assert len(rel.sections) >= 3
        assert "# Release Notes — Unreleased" in rel.markdown

        # 3. Breaking changes detection
        brk = run_breaking_change_detection(
            repo_path=sample_git_repo,
            base_ref="v0.1.0",
            target_ref="v0.2.0",
            use_llm=False,
        )
        assert brk.status == "ok"
        assert brk.llm_backend_status == "deterministic_engine"
        assert brk.warnings == []
        assert brk.total_potential_breaking_changes >= 4


def test_11_breaking_change_detection_ast_precision_and_evidence(sample_git_repo: Path) -> None:
    """Scenario 10 & 11: Breaking change detection, griffe#469/498/501 fixes, caller blast radius, doc drift, and evidence."""
    brk = detect_potential_breaking_changes(
        repo_path=str(sample_git_repo),
        base_ref="v0.1.0",
        target_ref="v0.2.0",
        include_low_confidence=False,
        use_llm=False,
    )
    assert brk["status"] == "ok"
    findings = brk["potential_breaking_changes"]
    assert len(findings) >= 4

    symbols_flagged = {f["affected_symbol"] for f in findings}
    change_kinds = {(f["affected_symbol"], f["change_kind"]) for f in findings}

    # 1. Removed function `legacy_refund`
    assert ("legacy_refund", "removed") in change_kinds
    # 2. `charge_card` signature change, return type change, decorator change, and newly raised ValueError (griffe#498)
    assert ("charge_card", "signature_changed") in change_kinds
    assert ("charge_card", "return_type_changed") in change_kinds
    assert ("charge_card", "decorator_changed") in change_kinds
    assert ("charge_card", "exception_raised_added") in change_kinds
    # 3. `Currency` base class changed from (str, Enum) to (Enum) (griffe#501)
    assert ("Currency", "base_class_changed") in change_kinds
    # 4. TypeScript `fetchInvoice` signature change
    assert ("fetchInvoice", "signature_changed") in change_kinds
    # 5. `connect_gateway` changed default from 30 to None WITH `if timeout is None:` guard (griffe#469) -> NOT flagged as breaking!
    assert "connect_gateway" not in symbols_flagged

    # Verify every finding has ground-truth evidence, caller blast-radius, and "Requires Human Review" framing
    charge_finding = next(f for f in findings if f["affected_symbol"] == "charge_card" and f["change_kind"] == "signature_changed")
    assert "Requires Human Review" in charge_finding["title"] or "Requires Review" in charge_finding["title"]
    assert len(charge_finding["observed_facts"]) >= 2
    assert charge_finding["model_interpretation"]
    assert len(charge_finding["potential_risks_requiring_verification"]) >= 1
    assert len(charge_finding["evidence"]) >= 1
    ev0 = charge_finding["evidence"][0]
    assert len(ev0["commit_hash"]) == 40
    assert ev0["file_path"] == "src/payments.py"
    assert ev0["base_line_span"] is not None

    # Verify downstream caller in src/checkout.py was detected via exact_ast
    caller_files = [c["caller_file"] for c in charge_finding["affected_callers"]]
    assert "src/checkout.py" in caller_files
    assert charge_finding["affected_callers"][0]["resolution_confidence"] == "exact_ast"

    # Verify README.md doc drift was detected
    drift_files = [d["doc_file"] for d in brk["doc_drift"]]
    assert "README.md" in drift_files


def test_12_mcp_input_validation_and_secret_redaction(sample_git_repo: Path) -> None:
    """Scenario 12: MCP input validation and secret redaction."""
    bad_max = inspect_repository(str(sample_git_repo), max_recent_commits=0)
    assert bad_max["status"] == "error"
    assert bad_max["error_code"] == "INVALID_MAX_COMMITS"

    bad_aud = generate_release_notes(str(sample_git_repo), base_ref="v0.1.0", target_ref="v0.2.0", audience="invalid_role", use_llm=False)
    assert bad_aud["status"] == "error"
    assert bad_aud["error_code"] == "INVALID_AUDIENCE"

    redacted = redact_secrets("Here is a leaked key: sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
    assert "sk-proj-" not in redacted
    assert "[REDACTED_OPENAI_KEY]" in redacted


@pytest.mark.ollama
def test_14_live_ollama_qwen25_coder_7b_integration(sample_git_repo: Path) -> None:
    """Scenario 14: Live integration test against local Ollama qwen2.5-coder:7b."""
    import os

    if os.environ.get("ATHENA_RUN_OLLAMA_TESTS", "").lower() not in ("1", "true", "yes"):
        pytest.skip("Set ATHENA_RUN_OLLAMA_TESTS=1 to run the live local Ollama integration test.")
    ready, reason = check_ollama_model_ready()
    assert ready is True, f"Mandatory local model qwen2.5-coder:7b must be available in Ollama: {reason}"

    report = run_git_history_analysis(
        repo_path=sample_git_repo,
        base_ref="v0.1.0",
        target_ref="v0.2.0",
        use_llm=True,
        timeout_seconds=90.0,
    )
    assert report.status == "ok"
    assert report.llm_backend_status == "ollama:qwen2.5-coder:7b"
    assert len(report.stories) >= 1
    for story in report.stories:
        assert len(story.evidence_ids) >= 1
        assert len(story.evidence) >= 1
        for ev in story.evidence:
            assert ev.evidence_id in report.evidence_registry
