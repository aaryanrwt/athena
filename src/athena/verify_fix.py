"""Closed-Loop Compiler, Test, and AST Remediation Verifier (`athena verify-fix` & `athena repair`).

Combines deterministic AST blast-radius re-auditing with real local compiler/typechecker
checks, targeted affected-test execution, universal AI provider iterations, and atomic
working-tree rollback when verification gates fail.
"""

from __future__ import annotations

import os
import re
import shutil
# Toolchains and test runners are executed strictly via allowlisted argv lists with shell=False.
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from athena.ai_providers import (
    AIProviderPatchResult,
    AIRepairTask,
    SUPPORTED_AI_PROVIDERS,
    build_ai_repair_tasks,
    invoke_ai_provider_for_task,
    resolve_ai_provider,
)
from athena.ast_analyzer import run_structural_code_analysis
from athena.evidence_store import truncate_head_tail
from athena.git_inspector import extract_revision_range_data
from athena.ollama_engine import DEFAULT_OLLAMA_BASE_URL
from athena.remediation import (
    FixPatch,
    FixPlanReport,
    _apply_patches_safely,
    capture_file_snapshots,
    generate_fix_plan,
    restore_file_snapshots,
)
from athena.security import AthenaValidationError, is_safe_repo_file, redact_model, redact_secrets, validate_repo_path
from athena.test_selector import predict_affected_tests


class CommandCheckResult(BaseModel):
    """Execution summary for one compiler, typechecker, or test command."""

    tool: str
    status: Literal["passed", "failed", "skipped_tool_missing", "skipped_no_targets", "timed_out"]
    command: str
    exit_code: int | None = None
    duration_ms: float = 0.0
    output_excerpt: str = ""
    truncated: bool = False


class VerifyFixReport(BaseModel):
    """Output contract for ``athena verify-fix`` and ``verify_fix`` MCP tool."""

    status: Literal["ok", "error"]
    verified_ok: bool = False
    repo_path: str
    base_ref: str
    target_ref: str
    remaining_breaking_findings_count: int = 0
    remaining_broken_callers_count: int = 0
    remaining_public_api_breaks_count: int = 0
    remaining_doc_drift_count: int = 0
    typecheck_results: list[CommandCheckResult] = Field(default_factory=list)
    test_results: list[CommandCheckResult] = Field(default_factory=list)
    affected_tests_selected: list[str] = Field(default_factory=list)
    feedback_for_ai: str = ""
    summary: str = ""
    error_code: str | None = None
    error_message: str | None = None


class RepairIterationRecord(BaseModel):
    """Telemetry for a single closed-loop AI repair + verification cycle."""

    iteration: int = Field(ge=1)
    provider: str
    model: str | None = None
    ai_patches_proposed: int = 0
    ai_patches_applied: int = 0
    conflicts_count: int = 0
    task_results: list[AIProviderPatchResult] = Field(default_factory=list)
    verification: VerifyFixReport | None = None


class ClosedLoopRepairReport(BaseModel):
    """Output contract for ``athena repair`` and ``run_ai_repair`` MCP tool."""

    status: Literal["ok", "error"]
    repo_path: str
    base_ref: str
    target_ref: str
    provider_requested: str
    provider_used: str
    model_used: str | None = None
    dry_run: bool = True
    mechanical_fix_plan: FixPlanReport | None = None
    ai_repair_tasks: list[AIRepairTask] = Field(default_factory=list)
    ai_patches: list[FixPatch] = Field(default_factory=list)
    iterations: list[RepairIterationRecord] = Field(default_factory=list)
    final_verification: VerifyFixReport | None = None
    verified_ok: bool = False
    rolled_back: bool = False
    summary: str = ""
    error_code: str | None = None
    error_message: str | None = None


def _which_cmd(*names: str) -> str | None:
    for name in names:
        hit = shutil.which(name)
        if hit:
            return hit
    return None


def _repo_has_dotnet_project(repo_root: Path) -> bool:
    for pat in ("*.sln", "*.csproj"):
        if list(repo_root.glob(pat)):
            return True
    try:
        for child in repo_root.iterdir():
            if child.is_dir() and not child.name.startswith("."):
                for pat in ("*.sln", "*.csproj"):
                    if list(child.glob(pat)):
                        return True
    except OSError:
        pass
    return False


def _has_dotnet_sdk(dotnet_bin: str | None) -> bool:
    if not dotnet_bin:
        return False
    try:
        proc = subprocess.run(
            [dotnet_bin, "--list-sdks"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            timeout=3,
            check=False,
        )
        return proc.returncode == 0 and bool((proc.stdout or "").strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def detect_available_toolchains(repo_root: Path | None = None) -> dict[str, Any]:
    """Detect installed compilers, typecheckers, test runners, and active project manifests."""
    dotnet_bin = _which_cmd("dotnet.exe", "dotnet")
    binaries: dict[str, str | None] = {
        "python": sys.executable,
        "mypy": _which_cmd("mypy.exe", "mypy"),
        "pyright": _which_cmd("pyright.cmd", "pyright"),
        "go": _which_cmd("go.exe", "go"),
        "cargo": _which_cmd("cargo.exe", "cargo"),
        "node": _which_cmd("node.exe", "node"),
        "tsc": _which_cmd("tsc.cmd", "tsc"),
        "dotnet": dotnet_bin if _has_dotnet_sdk(dotnet_bin) else None,
        "php": _which_cmd("php.exe", "php"),
        "swift": _which_cmd("swift.exe", "swift"),
        "javac": _which_cmd("javac.exe", "javac"),
    }
    manifests: list[str] = []
    if repo_root is not None and repo_root.is_dir():
        for name in ("pyproject.toml", "setup.py", "go.mod", "Cargo.toml", "tsconfig.json", "package.json", "composer.json", "Package.swift", "pom.xml", "build.gradle"):
            if (repo_root / name).is_file():
                manifests.append(name)
        if _repo_has_dotnet_project(repo_root):
            manifests.append("*.csproj/*.sln")
        local_tsc = repo_root / "node_modules" / ".bin" / ("tsc.cmd" if sys.platform == "win32" else "tsc")
        if local_tsc.is_file() and binaries["tsc"] is None:
            binaries["tsc"] = str(local_tsc)

    return {
        "available": {k: bool(v) for k, v in binaries.items()},
        "manifests_detected": manifests,
    }


def _exec_check_cmd(
    tool_name: str,
    cmd: list[str],
    repo_root: Path,
    *,
    timeout_sec: int,
    extra_env: dict[str, str] | None = None,
) -> CommandCheckResult:
    """Run an allowlisted verification command with shell=False and bounded output."""
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            timeout=timeout_sec,
            env=env,
            check=False,
        )
        dur_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        combined = "\n".join(part for part in ((proc.stdout or "").strip(), (proc.stderr or "").strip()) if part)
        redacted = redact_secrets(combined)
        excerpt, was_trunc, _ = truncate_head_tail(redacted, max_chars=2500)
        return CommandCheckResult(
            tool=tool_name,
            status="passed" if proc.returncode == 0 else "failed",
            command=" ".join(cmd[:8]) + (" ..." if len(cmd) > 8 else ""),
            exit_code=proc.returncode,
            duration_ms=dur_ms,
            output_excerpt=excerpt,
            truncated=was_trunc,
        )
    except subprocess.TimeoutExpired as exc:
        dur_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        raw_out = redact_secrets(str(exc.stdout or "") + "\n" + str(exc.stderr or ""))
        excerpt, was_trunc, _ = truncate_head_tail(raw_out.strip() or f"Timed out after {timeout_sec}s", max_chars=2500)
        return CommandCheckResult(
            tool=tool_name,
            status="timed_out",
            command=" ".join(cmd[:8]),
            exit_code=None,
            duration_ms=dur_ms,
            output_excerpt=excerpt,
            truncated=was_trunc,
        )
    except OSError as exc:
        return CommandCheckResult(
            tool=tool_name,
            status="skipped_tool_missing",
            command=" ".join(cmd[:4]),
            exit_code=None,
            duration_ms=0.0,
            output_excerpt=redact_secrets(f"Executable unavailable: {exc}"),
        )


def _python_typecheck_configured(repo_root: Path) -> tuple[bool, bool]:
    """Return (has_mypy_config, has_pyright_config) cleanly."""
    has_mypy = (repo_root / "mypy.ini").is_file() or (repo_root / ".mypy.ini").is_file()
    has_pyright = (repo_root / "pyrightconfig.json").is_file()
    pyproj = repo_root / "pyproject.toml"
    if pyproj.is_file():
        try:
            txt = pyproj.read_text(encoding="utf-8", errors="ignore")
            if "[tool.mypy]" in txt:
                has_mypy = True
            if "[tool.pyright]" in txt:
                has_pyright = True
        except OSError:
            pass
    return has_mypy, has_pyright


def _run_typechecks(
    repo_root: Path,
    candidate_files: list[str],
    *,
    timeout_sec: int,
) -> list[CommandCheckResult]:
    results: list[CommandCheckResult] = []
    existing = [
        rel
        for rel in sorted(set(candidate_files))
        if (repo_root / rel).is_file() and is_safe_repo_file(repo_root, repo_root / rel)
    ]

    # 1. Python syntax compilation + optional configured typecheckers
    py_files = [f for f in existing if f.endswith(".py")][:50]
    if py_files:
        results.append(
            _exec_check_cmd(
                "python:py_compile",
                [sys.executable, "-m", "py_compile", *py_files],
                repo_root,
                timeout_sec=timeout_sec,
            )
        )
        has_mypy, has_pyright = _python_typecheck_configured(repo_root)
        if has_mypy:
            mypy_bin = _which_cmd("mypy.exe", "mypy")
            if mypy_bin:
                results.append(
                    _exec_check_cmd(
                        "mypy",
                        [mypy_bin, "--follow-imports=silent", *py_files[:20]],
                        repo_root,
                        timeout_sec=timeout_sec,
                    )
                )
        if has_pyright:
            pyr_bin = _which_cmd("pyright.cmd", "pyright")
            if pyr_bin:
                results.append(
                    _exec_check_cmd(
                        "pyright",
                        [pyr_bin, *py_files[:20]],
                        repo_root,
                        timeout_sec=timeout_sec,
                    )
                )

    # 2. Go (`go vet`)
    go_files = [f for f in existing if f.endswith(".go")]
    if go_files and (repo_root / "go.mod").is_file():
        go_bin = _which_cmd("go.exe", "go")
        if go_bin:
            pkg_dirs = sorted({("./" + str(Path(f).parent).replace("\\", "/")) if Path(f).parent != Path(".") else "." for f in go_files})
            results.append(
                _exec_check_cmd("go:vet", [go_bin, "vet", *pkg_dirs[:15]], repo_root, timeout_sec=timeout_sec)
            )
        else:
            results.append(CommandCheckResult(tool="go:vet", status="skipped_tool_missing", command="go vet"))

    # 3. Rust (`cargo check`)
    rs_files = [f for f in existing if f.endswith(".rs")]
    if rs_files and (repo_root / "Cargo.toml").is_file():
        cargo_bin = _which_cmd("cargo.exe", "cargo")
        if cargo_bin:
            results.append(
                _exec_check_cmd("cargo:check", [cargo_bin, "check", "--quiet"], repo_root, timeout_sec=timeout_sec)
            )
        else:
            results.append(CommandCheckResult(tool="cargo:check", status="skipped_tool_missing", command="cargo check"))

    # 4. TypeScript (`tsc --noEmit`) & JavaScript (`node --check`)
    ts_files = [f for f in existing if f.endswith((".ts", ".tsx", ".mts", ".cts"))]
    if ts_files and (repo_root / "tsconfig.json").is_file():
        local_tsc = repo_root / "node_modules" / ".bin" / ("tsc.cmd" if sys.platform == "win32" else "tsc")
        tsc_bin = str(local_tsc) if local_tsc.is_file() else _which_cmd("tsc.cmd", "tsc")
        if tsc_bin:
            results.append(
                _exec_check_cmd("tsc", [tsc_bin, "--noEmit"], repo_root, timeout_sec=timeout_sec)
            )
        else:
            results.append(CommandCheckResult(tool="tsc", status="skipped_tool_missing", command="tsc --noEmit"))

    js_files = [f for f in existing if f.endswith((".js", ".mjs", ".cjs"))][:25]
    if js_files:
        node_bin = _which_cmd("node.exe", "node")
        if node_bin:
            for jf in js_files:
                res = _exec_check_cmd("node:check", [node_bin, "--check", jf], repo_root, timeout_sec=timeout_sec)
                results.append(res)
                if res.status != "passed":
                    break

    # 5. C# (`dotnet build`)
    cs_files = [f for f in existing if f.endswith(".cs")]
    if cs_files and _repo_has_dotnet_project(repo_root):
        dotnet_bin = _which_cmd("dotnet.exe", "dotnet")
        if dotnet_bin and _has_dotnet_sdk(dotnet_bin):
            cmd = [dotnet_bin, "build", "--nologo", "-v", "quiet"]
            if any(repo_root.glob("**/obj/project.assets.json")):
                cmd.insert(2, "--no-restore")
            results.append(_exec_check_cmd("dotnet:build", cmd, repo_root, timeout_sec=timeout_sec))
        else:
            results.append(
                CommandCheckResult(
                    tool="dotnet:build",
                    status="skipped_tool_missing",
                    command="dotnet build",
                    output_excerpt="No .NET SDK installed (`dotnet --list-sdks` empty).",
                )
            )

    # 6. PHP (`php -l`)
    php_files = [f for f in existing if f.endswith(".php")][:25]
    if php_files:
        php_bin = _which_cmd("php.exe", "php")
        if php_bin:
            for pf in php_files:
                res = _exec_check_cmd("php:lint", [php_bin, "-l", pf], repo_root, timeout_sec=timeout_sec)
                results.append(res)
                if res.status != "passed":
                    break

    return results


def _run_affected_tests(
    repo_root: Path,
    selected_tests: list[str],
    candidate_files: list[str],
    *,
    timeout_sec: int,
) -> list[CommandCheckResult]:
    results: list[CommandCheckResult] = []
    existing_tests = [
        t
        for t in selected_tests
        if (repo_root / t).is_file() and is_safe_repo_file(repo_root, repo_root / t)
    ]

    # Python pytest on impacted test files
    py_tests = [t for t in existing_tests if t.endswith(".py")]
    if py_tests:
        py_path_entries = [str(repo_root)]
        if (repo_root / "src").is_dir():
            py_path_entries.insert(0, str(repo_root / "src"))
        if os.environ.get("PYTHONPATH"):
            py_path_entries.append(os.environ["PYTHONPATH"])
        results.append(
            _exec_check_cmd(
                "pytest",
                [sys.executable, "-m", "pytest", "-q", "--no-header", *py_tests],
                repo_root,
                timeout_sec=timeout_sec,
                extra_env={"PYTHONPATH": os.pathsep.join(py_path_entries), "PYTHONDONTWRITEBYTECODE": "1"},
            )
        )

    # Go test on impacted Go packages
    go_tests = [t for t in existing_tests if t.endswith("_test.go")]
    if go_tests and (repo_root / "go.mod").is_file():
        go_bin = _which_cmd("go.exe", "go")
        if go_bin:
            pkg_dirs = sorted({("./" + str(Path(f).parent).replace("\\", "/")) if Path(f).parent != Path(".") else "." for f in go_tests})
            results.append(_exec_check_cmd("go:test", [go_bin, "test", *pkg_dirs[:15]], repo_root, timeout_sec=timeout_sec))
        else:
            results.append(CommandCheckResult(tool="go:test", status="skipped_tool_missing", command="go test"))

    # Rust cargo test when Rust files or Cargo tests touched
    rs_touched = any(t.endswith(".rs") for t in existing_tests) or any(f.endswith(".rs") for f in candidate_files)
    if rs_touched and (repo_root / "Cargo.toml").is_file() and (existing_tests or any(f.endswith(".rs") for f in candidate_files)):
        cargo_bin = _which_cmd("cargo.exe", "cargo")
        if cargo_bin:
            results.append(_exec_check_cmd("cargo:test", [cargo_bin, "test", "--quiet"], repo_root, timeout_sec=timeout_sec))
        else:
            results.append(CommandCheckResult(tool="cargo:test", status="skipped_tool_missing", command="cargo test"))

    # .NET test when C# test files impacted
    cs_tests = [t for t in existing_tests if t.endswith(".cs")]
    if cs_tests and _repo_has_dotnet_project(repo_root):
        dotnet_bin = _which_cmd("dotnet.exe", "dotnet")
        if dotnet_bin and _has_dotnet_sdk(dotnet_bin):
            cmd = [dotnet_bin, "test", "--nologo", "-v", "quiet"]
            if any(repo_root.glob("**/obj/project.assets.json")):
                cmd.insert(2, "--no-restore")
            results.append(_exec_check_cmd("dotnet:test", cmd, repo_root, timeout_sec=timeout_sec))
        else:
            results.append(
                CommandCheckResult(
                    tool="dotnet:test",
                    status="skipped_tool_missing",
                    command="dotnet test",
                    output_excerpt="No .NET SDK installed (`dotnet --list-sdks` empty).",
                )
            )

    return results


def verify_fix_state(
    repo_path: str | Path,
    base_ref: str = "AUTO",
    target_ref: str = "WORKING_TREE",
    *,
    run_typecheck: bool = True,
    run_tests: bool = True,
    max_test_files: int = 20,
    timeout_sec: int = 120,
) -> VerifyFixReport:
    """Verify repairs via Athena AST re-audit, compiler/typecheck gates, and affected tests."""
    if isinstance(max_test_files, bool) or not isinstance(max_test_files, int) or max_test_files < 1 or max_test_files > 100:
        return VerifyFixReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            error_code="INVALID_MAX_TESTS",
            error_message="max_test_files must be an integer between 1 and 100.",
        )

    try:
        repo_root = validate_repo_path(repo_path)
        extraction = extract_revision_range_data(
            repo_path_input=repo_root,
            base_ref=base_ref,
            target_ref=target_ref,
            max_commits=100,
        )
    except AthenaValidationError as exc:
        return VerifyFixReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            error_code=exc.code,
            error_message=exc.message,
        )

    structural = run_structural_code_analysis(extraction)
    active_findings = [f for f in structural.deterministic_breaking_findings if f.confidence != "low"]

    broken_callers_total = 0
    caller_feedback_lines: list[str] = []
    candidate_files: list[str] = [cf.file_path for cf in extraction.changed_files]

    for f in active_findings:
        for c in f.affected_callers:
            candidate_files.append(c.caller_file)
            if c.arity_mismatch_detected or f.change_kind == "removed":
                broken_callers_total += 1
                if len(caller_feedback_lines) < 10:
                    caller_feedback_lines.append(
                        f"- Remaining broken caller at `{c.caller_file}:{c.line_number}` calling `{f.affected_symbol}`: {c.mismatch_details or f.change_kind}"
                    )

    public_api_breaks = sum(1 for f in active_findings if f.is_public_api_export)

    selected_tests: list[str] = []
    try:
        tests_rep = predict_affected_tests(
            repo_root,
            base_ref=extraction.resolved_base_sha,
            target_ref=extraction.resolved_target_sha,
            limit=max_test_files,
        )
        selected_tests = [str(item["test_file"]) for item in tests_rep.get("selected_tests", [])]
    except AthenaValidationError:
        selected_tests = []

    typecheck_results: list[CommandCheckResult] = []
    if run_typecheck:
        typecheck_results = _run_typechecks(repo_root, candidate_files, timeout_sec=timeout_sec)

    test_results: list[CommandCheckResult] = []
    if run_tests:
        test_results = _run_affected_tests(repo_root, selected_tests, candidate_files, timeout_sec=timeout_sec)

    tc_failed = any(r.status in ("failed", "timed_out") for r in typecheck_results)
    tests_failed = any(r.status in ("failed", "timed_out") for r in test_results)
    verified_ok = (broken_callers_total == 0) and (not tc_failed) and (not tests_failed)

    feedback_parts: list[str] = []
    if caller_feedback_lines:
        feedback_parts.append("AST Breaking Callers:\n" + "\n".join(caller_feedback_lines))
    for r in typecheck_results:
        if r.status in ("failed", "timed_out"):
            feedback_parts.append(f"Typecheck `{r.tool}` failed:\n{r.output_excerpt}")
    for r in test_results:
        if r.status in ("failed", "timed_out"):
            feedback_parts.append(f"Tests `{r.tool}` failed:\n{r.output_excerpt}")
    feedback_str = redact_secrets("\n\n".join(feedback_parts))

    tc_summary = f"{sum(1 for r in typecheck_results if r.status == 'passed')}/{len(typecheck_results)} typecheck(s) passed" if typecheck_results else "no typechecks executed"
    ts_summary = f"{sum(1 for r in test_results if r.status == 'passed')}/{len(test_results)} test run(s) passed" if test_results else "no tests executed"
    summary = (
        f"verified_ok={verified_ok}: remaining_broken_callers={broken_callers_total}, "
        f"remaining_breaking_findings={len(active_findings)} (public_external={public_api_breaks}), "
        f"{tc_summary}, {ts_summary}."
    )

    return redact_model(
        VerifyFixReport(
            status="ok",
            verified_ok=verified_ok,
            repo_path=str(repo_root),
            base_ref=extraction.base_ref,
            target_ref=extraction.target_ref,
            remaining_breaking_findings_count=len(active_findings),
            remaining_broken_callers_count=broken_callers_total,
            remaining_public_api_breaks_count=public_api_breaks,
            remaining_doc_drift_count=len(structural.doc_drift_items),
            typecheck_results=typecheck_results,
            test_results=test_results,
            affected_tests_selected=selected_tests,
            feedback_for_ai=feedback_str,
            summary=summary,
        )
    )


def run_closed_loop_repair(
    repo_path: str | Path,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    *,
    provider: str = "auto",
    model: str | None = None,
    base_url: str | None = None,
    apply: bool = False,
    include_review_required: bool = False,
    include_low_confidence: bool = False,
    max_iterations: int = 2,
    max_tasks: int = 10,
    run_typecheck: bool = True,
    run_tests: bool = True,
    rollback_on_fail: bool = True,
    timeout_sec: int = 120,
) -> ClosedLoopRepairReport:
    """Execute detect -> mechanical fix -> AI repair -> compiler/test/AST verification loop."""
    clean_provider = (provider or "auto").strip().lower()
    if clean_provider not in SUPPORTED_AI_PROVIDERS:
        return ClosedLoopRepairReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            provider_requested=str(provider),
            provider_used="none",
            dry_run=not apply,
            error_code="INVALID_AI_PROVIDER",
            error_message=f"Unsupported AI provider '{provider}'. Choose from: {', '.join(SUPPORTED_AI_PROVIDERS)}.",
        )
    if isinstance(max_iterations, bool) or not isinstance(max_iterations, int) or max_iterations < 1 or max_iterations > 5:
        return ClosedLoopRepairReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            provider_requested=clean_provider,
            provider_used="none",
            dry_run=not apply,
            error_code="INVALID_MAX_ITERATIONS",
            error_message="max_iterations must be an integer between 1 and 5.",
        )

    try:
        repo_root = validate_repo_path(repo_path)
        resolved_prov = resolve_ai_provider(
            clean_provider,
            ollama_url=base_url or DEFAULT_OLLAMA_BASE_URL,
        )
        initial_extraction = extract_revision_range_data(
            repo_path_input=repo_root,
            base_ref=base_ref,
            target_ref=target_ref,
            max_commits=100,
        )
    except AthenaValidationError as exc:
        return ClosedLoopRepairReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            provider_requested=clean_provider,
            provider_used="none",
            dry_run=not apply,
            error_code=exc.code,
            error_message=exc.message,
        )

    verify_base_sha = initial_extraction.resolved_base_sha
    initial_structural = run_structural_code_analysis(initial_extraction)

    # Plan Layer 1 deterministic mechanical fixes first (always dry-run before capturing rollback snapshot)
    mech_plan = generate_fix_plan(
        repo_root,
        base_ref=verify_base_sha,
        target_ref=initial_extraction.resolved_target_sha,
        apply=False,
        include_review_required=include_review_required,
        include_low_confidence=include_low_confidence,
    )

    affected_tests_list: list[str] = []
    try:
        t_rep = predict_affected_tests(
            repo_root,
            base_ref=verify_base_sha,
            target_ref=initial_extraction.resolved_target_sha,
            limit=20,
        )
        affected_tests_list = [str(item["test_file"]) for item in t_rep.get("selected_tests", [])]
    except AthenaValidationError:
        pass

    ai_tasks = build_ai_repair_tasks(
        repo_root,
        initial_extraction,
        initial_structural,
        mech_plan,
        max_tasks=max_tasks,
        include_low_confidence=include_low_confidence,
        affected_tests=affected_tests_list,
    )

    snapshots: dict[str, tuple[bool, str | None]] = {}
    if apply:
        mech_files = [
            p.file_path
            for p in mech_plan.patches
            if p.edits and (p.applicability == "safe" or include_review_required)
        ]
        task_files = [af for t in ai_tasks for af in t.allowed_files]
        snapshots = capture_file_snapshots(repo_root, [*mech_files, *task_files])
        applied_m, conflicts_m = _apply_patches_safely(
            repo_root,
            mech_plan.patches,
            include_review_required=include_review_required,
        )
        mech_plan.dry_run = False
        mech_plan.applied_count = applied_m
        mech_plan.skipped_conflicts_count = conflicts_m

    iterations: list[RepairIterationRecord] = []
    all_ai_patches: list[FixPatch] = []
    final_verify: VerifyFixReport | None = None
    chosen_model = model or resolved_prov.default_model

    # Handle handoff mode or cleanly solved-by-codemod repos without AI loop
    if resolved_prov.provider == "handoff" or not ai_tasks:
        final_verify = verify_fix_state(
            repo_root,
            base_ref=verify_base_sha,
            target_ref="WORKING_TREE" if apply else initial_extraction.resolved_target_sha,
            run_typecheck=run_typecheck,
            run_tests=run_tests,
            timeout_sec=timeout_sec,
        )
        rolled_back = False
        if apply and rollback_on_fail and not final_verify.verified_ok and snapshots and not ai_tasks:
            restore_file_snapshots(repo_root, snapshots)
            rolled_back = True
        summary = (
            f"Mechanical codemods planned={mech_plan.total_patches} (safe={mech_plan.safe_patches_count}, "
            f"applied={mech_plan.applied_count}); AI repair tasks={len(ai_tasks)} (provider={resolved_prov.provider}); "
            f"verified_ok={final_verify.verified_ok}."
        )
        return redact_model(
            ClosedLoopRepairReport(
                status="ok",
                repo_path=str(repo_root),
                base_ref=initial_extraction.base_ref,
                target_ref=initial_extraction.target_ref,
                provider_requested=clean_provider,
                provider_used=resolved_prov.provider,
                model_used=chosen_model,
                dry_run=not apply,
                mechanical_fix_plan=mech_plan,
                ai_repair_tasks=ai_tasks,
                ai_patches=[],
                iterations=[],
                final_verification=final_verify,
                verified_ok=final_verify.verified_ok,
                rolled_back=rolled_back,
                summary=summary,
            )
        )

    # Closed-loop AI repair iterations
    feedback = ""
    if apply and (run_typecheck or run_tests):
        pre_verify = verify_fix_state(
            repo_root,
            base_ref=verify_base_sha,
            target_ref="WORKING_TREE",
            run_typecheck=run_typecheck,
            run_tests=run_tests,
            timeout_sec=timeout_sec,
        )
        if pre_verify.verified_ok:
            return redact_model(
                ClosedLoopRepairReport(
                    status="ok",
                    repo_path=str(repo_root),
                    base_ref=initial_extraction.base_ref,
                    target_ref=initial_extraction.target_ref,
                    provider_requested=clean_provider,
                    provider_used=resolved_prov.provider,
                    model_used=chosen_model,
                    dry_run=False,
                    mechanical_fix_plan=mech_plan,
                    ai_repair_tasks=ai_tasks,
                    ai_patches=[],
                    iterations=[],
                    final_verification=pre_verify,
                    verified_ok=True,
                    rolled_back=False,
                    summary=f"Verification already passed after deterministic fixes: {pre_verify.summary}",
                )
            )
        feedback = pre_verify.feedback_for_ai

    for iter_idx in range(1, max_iterations + 1):
        # Rebuild fresh task context on iteration 2+ so AI sees updated disk lines
        cur_tasks = ai_tasks
        if iter_idx > 1:
            cur_ext = extract_revision_range_data(repo_root, base_ref=verify_base_sha, target_ref="WORKING_TREE", max_commits=100)
            cur_struct = run_structural_code_analysis(cur_ext)
            cur_tasks = build_ai_repair_tasks(
                repo_root,
                cur_ext,
                cur_struct,
                mech_plan,
                max_tasks=max_tasks,
                include_low_confidence=include_low_confidence,
                affected_tests=affected_tests_list,
            ) or ai_tasks

        iter_results: list[AIProviderPatchResult] = []
        iter_patches: list[FixPatch] = []
        for task in cur_tasks:
            res = invoke_ai_provider_for_task(
                repo_root,
                task,
                provider=resolved_prov.provider,
                model=chosen_model,
                base_url=base_url,
                feedback=feedback,
                timeout_sec=timeout_sec,
            )
            iter_results.append(res)
            for pt in res.patches:
                pt.fix_id = f"ai_it{iter_idx}_{pt.fix_id}"
                iter_patches.append(pt)

        all_ai_patches.extend(iter_patches)
        if not apply:
            final_verify = verify_fix_state(
                repo_root,
                base_ref=verify_base_sha,
                target_ref=initial_extraction.resolved_target_sha,
                run_typecheck=False,
                run_tests=False,
                timeout_sec=timeout_sec,
            )
            iterations.append(
                RepairIterationRecord(
                    iteration=iter_idx,
                    provider=resolved_prov.provider,
                    model=chosen_model,
                    ai_patches_proposed=len(iter_patches),
                    ai_patches_applied=0,
                    conflicts_count=0,
                    task_results=iter_results,
                    verification=final_verify,
                )
            )
            break

        applied_ai, conflicts_ai = _apply_patches_safely(
            repo_root,
            iter_patches,
            include_review_required=True,
        )
        final_verify = verify_fix_state(
            repo_root,
            base_ref=verify_base_sha,
            target_ref="WORKING_TREE",
            run_typecheck=run_typecheck,
            run_tests=run_tests,
            timeout_sec=timeout_sec,
        )
        iterations.append(
            RepairIterationRecord(
                iteration=iter_idx,
                provider=resolved_prov.provider,
                model=chosen_model,
                ai_patches_proposed=len(iter_patches),
                ai_patches_applied=applied_ai,
                conflicts_count=conflicts_ai,
                task_results=iter_results,
                verification=final_verify,
            )
        )
        if final_verify.verified_ok:
            break
        feedback = final_verify.feedback_for_ai

    rolled_back = False
    verified_ok = bool(final_verify and final_verify.verified_ok)
    if apply and rollback_on_fail and not verified_ok and snapshots:
        restore_file_snapshots(repo_root, snapshots)
        rolled_back = True

    summary = (
        f"Athena + {resolved_prov.provider} closed-loop repair ({len(iterations)} iteration(s), dry_run={not apply}): "
        f"mechanical={mech_plan.applied_count}/{mech_plan.total_patches}, "
        f"ai_patches={len(all_ai_patches)}, verified_ok={verified_ok}, rolled_back={rolled_back}."
    )
    return redact_model(
        ClosedLoopRepairReport(
            status="ok",
            repo_path=str(repo_root),
            base_ref=initial_extraction.base_ref,
            target_ref=initial_extraction.target_ref,
            provider_requested=clean_provider,
            provider_used=resolved_prov.provider,
            model_used=chosen_model,
            dry_run=not apply,
            mechanical_fix_plan=mech_plan,
            ai_repair_tasks=ai_tasks,
            ai_patches=all_ai_patches,
            iterations=iterations,
            final_verification=final_verify,
            verified_ok=verified_ok,
            rolled_back=rolled_back,
            summary=summary,
        )
    )
