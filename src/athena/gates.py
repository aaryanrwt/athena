"""Semantic-version gate and staged-change helpers for CI / pre-commit usage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from athena.git_inspector import resolve_revision_sha, run_git_command
from athena.security import AthenaValidationError, validate_repo_path

BUMP_RANK = {"patch": 0, "minor": 1, "major": 2}


def required_bump(breaking_count: int, added_public_symbols: int) -> tuple[str, list[str]]:
    """Return (required bump, reasons) from deterministic counts."""
    if breaking_count > 0:
        return "major", [f"{breaking_count} potential breaking change(s) require a major bump."]
    if added_public_symbols > 0:
        return "minor", [f"{added_public_symbols} new public symbol(s) require at least a minor bump."]
    return "patch", ["No breaking changes or new public symbols detected; a patch bump is sufficient."]


def evaluate_semver_gate(declared: str, required: str) -> bool:
    """True when the declared bump is at least the required bump."""
    if declared not in BUMP_RANK or required not in BUMP_RANK:
        raise AthenaValidationError("INVALID_BUMP", f"Bump must be one of major, minor, patch (got '{declared}').")
    return BUMP_RANK[declared] >= BUMP_RANK[required]


def semver_check(repo_path: str, base: str, target: str, declared: str) -> dict[str, Any]:
    """Run deterministic analysis and compare the declared bump with the required one."""
    from athena.release_notes import run_breaking_change_detection, run_git_history_analysis

    if declared not in BUMP_RANK:
        raise AthenaValidationError("INVALID_BUMP", f"--declared must be one of major, minor, patch (got '{declared}').")
    brk = run_breaking_change_detection(repo_path=repo_path, base_ref=base, target_ref=target, use_llm=False)
    if brk.status != "ok":
        return {"status": "error", "error_code": brk.error_code, "error_message": brk.error_message}
    added = 0
    if brk.total_potential_breaking_changes == 0:
        hist = run_git_history_analysis(repo_path=repo_path, base_ref=base, target_ref=target, use_llm=False)
        if hist.status != "ok":
            return {"status": "error", "error_code": hist.error_code, "error_message": hist.error_message}
        added = sum(1 for s in hist.symbol_changes if s.change_kind == "added" and s.is_public_api_export)
    required, reasons = required_bump(brk.total_potential_breaking_changes, added)
    ok = evaluate_semver_gate(declared, required)
    return {
        "status": "ok",
        "base_ref": brk.base_ref,
        "target_ref": brk.target_ref,
        "declared_bump": declared,
        "required_bump": required,
        "gate_passed": ok,
        "reasons": reasons,
    }


def build_staged_target(repo_path: str | Path) -> tuple[Path, str] | None:
    """Snapshot the index as an unreachable commit on top of HEAD and return (repo, sha).

    Returns ``None`` when the repository has no HEAD commit yet. The snapshot is an
    unreferenced object that Git garbage-collects; no refs, index, or files are modified.
    """
    repo = validate_repo_path(repo_path)
    if run_git_command(repo, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], check=False).returncode != 0:
        return None
    tree = run_git_command(repo, ["write-tree"]).stdout.strip()
    sha = run_git_command(
        repo,
        [
            "-c", "user.name=athena",
            "-c", "user.email=athena@localhost",
            "-c", "commit.gpgsign=false",
            "commit-tree", tree, "-p", "HEAD", "-m", "athena staged snapshot",
        ],
    ).stdout.strip()
    return repo, resolve_revision_sha(repo, sha, "staged")


def check_staged(repo_path: str | Path) -> dict[str, Any]:
    """Deterministically analyze staged changes against HEAD for pre-commit use."""
    from athena.release_notes import run_breaking_change_detection

    try:
        snap = build_staged_target(repo_path)
    except AthenaValidationError as exc:
        return {"status": "error", "error_code": exc.code, "error_message": exc.message}
    if snap is None:
        return {"status": "ok", "total_potential_breaking_changes": 0, "potential_breaking_changes": [],
                "note": "Repository has no commits yet; nothing to compare against."}
    repo, sha = snap
    report = run_breaking_change_detection(repo_path=repo, base_ref="HEAD", target_ref=sha, use_llm=False)
    data = report.model_dump(mode="json")
    data["target_ref"] = "STAGED"
    return data
