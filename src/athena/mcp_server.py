"""Athena Model Context Protocol (MCP) Server Implementation."""

from __future__ import annotations

import inspect
import json
import os
from collections.abc import Callable, Sequence
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

try:
    from mcp.server.mcpserver import MCPServer

    _MCP_SUPPORTS_VERSION = True
except ImportError:  # pragma: no cover - fallback for mcp 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[no-redef]

    _MCP_SUPPORTS_VERSION = False

from mcp.types import ToolAnnotations

from athena import __version__
from athena.debt_tracker import scan_shortcut_debt
from athena.evidence_store import DEFAULT_EVIDENCE_STORE, resolve_completeness
from athena.git_inspector import inspect_repository_state
from athena.graph_query import (
    get_god_nodes,
    get_graph_stats,
    query_code_graph as _query_graph_engine,
    shortest_path_between,
)
from athena.graph_store import DEFAULT_GRAPH_MANAGER
from athena.ollama_engine import (
    DEFAULT_ENABLE_LLM,
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OLLAMA_MODEL,
)
from athena.release_notes import (
    run_breaking_change_detection,
    run_git_history_analysis,
    run_release_notes_generation,
)
from athena.remediation import generate_fix_plan
from athena.repo_map import build_repo_map
from athena.security import AthenaValidationError, redact_secrets
from athena.test_selector import predict_affected_tests
from athena.token_ledger import read_gain_report
from athena.treesitter_parser import get_treesitter_status

VALID_TOOLSETS: tuple[str, ...] = (
    "git",
    "graph",
    "analysis",
    "release",
    "debt",
    "testing",
    "evidence",
    "meta",
)
VALID_TRANSPORTS: tuple[str, ...] = ("stdio", "streamable-http")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

_REMEDIATION_HINTS: dict[str, tuple[bool, str]] = {
    "EMPTY_REPO_PATH": (False, "Provide a non-empty local Git repository directory path."),
    "REPO_PATH_NOT_FOUND": (False, "Verify the repository path exists and is readable."),
    "NOT_A_GIT_REPO": (False, "Initialize Git or pass the root directory of a valid Git repository."),
    "REVISION_NOT_FOUND": (False, "Verify that base_ref and target_ref exist locally (`git branch -a`, `git tag`)."),
    "INVALID_GIT_REF": (False, "Use valid Git ref names without leading dashes, '..' ranges, or whitespace."),
    "OUTPUT_FILE_EXISTS": (False, "Pass overwrite=True or choose a new relative output_file path."),
    "INVALID_AUDIENCE": (False, "Choose audience from: end_users, developers, maintainers, clients."),
    "EMPTY_REPO": (False, "Create at least one commit before analyzing Git history."),
    "GIT_EXECUTION_ERROR": (True, "Check local Git installation and repository integrity before retrying."),
    "INVALID_MAX_COMMITS": (False, "Set max_commits / max_recent_commits within the allowed positive range."),
    "INVALID_MAX_CHARS": (False, "Set max_chars to a positive integer (recommended: 500..4000)."),
    "INVALID_OFFSET": (False, "Set offset to a non-negative integer (>= 0)."),
    "INVALID_LIMIT": (False, "Set limit to a positive integer (1..500)."),
    "INVALID_TOOLSET": (False, f"Choose toolsets from: {', '.join(VALID_TOOLSETS)}, or 'all'."),
    "INVALID_TRANSPORT": (False, "Choose transport 'stdio' (default) or 'streamable-http'."),
    "INVALID_PORT": (False, "Set port to an integer between 1 and 65535."),
    "REMOTE_BIND_BLOCKED": (False, "Bind to 127.0.0.1/localhost or pass allow_remote=True intentionally."),
}


def _safe_exception_detail(exc: Exception) -> str:
    """Return an exception summary with credentials removed before MCP serialization."""
    return redact_secrets(f"{type(exc).__name__}: {exc}")


def _attach_error_recovery(payload: dict[str, Any]) -> dict[str, Any]:
    """Ensure every error response carries consistent recovery classification and hints."""
    if payload.get("status") != "error":
        return payload
    code = str(payload.get("error_code") or "UNKNOWN_ERROR")
    default_kind = "execution" if code in {"GIT_EXECUTION_ERROR"} or code.startswith("INTERNAL_") else "validation"
    default_retryable, default_hint = _REMEDIATION_HINTS.get(
        code,
        (default_kind != "validation", "Verify input arguments and repository state before retrying."),
    )
    payload.setdefault("error_kind", default_kind)
    payload.setdefault("retryable", default_retryable)
    payload.setdefault("remediation_action", default_hint)
    return payload


def _error_payload(
    error_code: str,
    error_message: str,
    *,
    error_kind: str = "validation",
    retryable: bool | None = None,
    remediation_action: str = "",
    **extra: Any,
) -> dict[str, Any]:
    """Build a structured MCP error dictionary with recovery guidance."""
    default_retryable, default_hint = _REMEDIATION_HINTS.get(
        error_code,
        (error_kind != "validation", "Verify input arguments and repository state before retrying."),
    )
    return {
        "status": "error",
        "error_code": error_code,
        "error_kind": error_kind,
        "retryable": default_retryable if retryable is None else retryable,
        "error_message": redact_secrets(error_message),
        "remediation_action": remediation_action or default_hint,
        **extra,
    }


def parse_toolsets(toolsets: str | Sequence[str] | None) -> tuple[str, ...]:
    """Validate and normalize requested MCP toolset filters."""
    if toolsets is None:
        return VALID_TOOLSETS
    if isinstance(toolsets, str):
        raw_items = [part.strip().lower() for part in toolsets.split(",") if part.strip()]
    else:
        raw_items = [str(part).strip().lower() for part in toolsets if str(part).strip()]
    if not raw_items or "all" in raw_items:
        return VALID_TOOLSETS

    invalid = [item for item in raw_items if item not in VALID_TOOLSETS]
    if invalid:
        raise AthenaValidationError(
            "INVALID_TOOLSET",
            f"Unknown toolset(s): {', '.join(invalid)}. Valid options: {', '.join(VALID_TOOLSETS)}, all.",
        )
    deduped = dict.fromkeys(raw_items)
    return tuple(deduped.keys())


def get_rust_acceleration_status() -> dict[str, Any]:
    """Report real runtime availability of Athena's compiled PyO3 Rust kernels."""
    from athena import _fast_kernels, security as sec_mod

    disabled_by_env = bool(os.environ.get("FAST_ANYTHING_DISABLE"))
    probes = {
        "redact_secrets": sec_mod.redact_secrets,
        "score_graph_trigrams": _fast_kernels.score_graph_trigrams,
        "compute_community_assignments": _fast_kernels.compute_community_assignments,
        "extract_structural_symbols_raw": _fast_kernels.extract_structural_symbols_raw,
    }
    kernels: dict[str, str] = {}
    active_count = 0
    for name, fn in probes.items():
        mod_name = getattr(fn, "__module__", "") or ""
        is_native = not mod_name.startswith("athena.")
        if is_native:
            active_count += 1
        kernels[name] = "rust" if is_native else "python"

    return {
        "disabled_by_env": disabled_by_env,
        "native_kernels_active": active_count,
        "total_accelerated_kernels": len(probes),
        "mode": "hybrid_rust" if active_count > 0 else "pure_python",
        "kernels": kernels,
    }


_MCP_INSTRUCTIONS = (
    f"Athena v{__version__} is an offline-capable, local-first multi-language Git intelligence and AST change analysis MCP server. "
    "Athena is created and maintained by Aaryan Rawat. "
    "All core operations (Git diff inspection, Python AST analysis, TypeScript/JS, C/C++, Go, Rust, Java, C#, Ruby, and PHP "
    "structural signature diffing, caller blast-radius scanning, doc drift detection, evidence verification, release notes, "
    "breaking change detection, resources, and workflow prompts) operate deterministically without requiring any LLM. "
    "Local Ollama (gemma:latest and qwen2.5-coder:7b) is an optional enhancement when use_llm=True is explicitly enabled. "
    "Analysis operations are read-only; release tools write only when an output_file is explicitly supplied."
)


def inspect_repository(
    repo_path: str,
    max_recent_commits: int = 10,
) -> dict[str, Any]:
    """Inspect a local Git repository and return a structured RepositoryStatusReport."""
    if not isinstance(repo_path, str) or not repo_path.strip():
        return _error_payload(
            "EMPTY_REPO_PATH",
            "Parameter 'repo_path' must be a non-empty directory path.",
            repo_path=str(repo_path),
            is_valid_git_repo=False,
        )
    if (
        isinstance(max_recent_commits, bool)
        or not isinstance(max_recent_commits, int)
        or max_recent_commits < 1
        or max_recent_commits > 100
    ):
        return _error_payload(
            "INVALID_MAX_COMMITS",
            "Parameter 'max_recent_commits' must be an integer between 1 and 100.",
            repo_path=repo_path,
            is_valid_git_repo=False,
        )
    try:
        report = inspect_repository_state(
            repo_path_input=repo_path,
            max_recent_commits=max_recent_commits,
        )
        return _attach_error_recovery(report.model_dump(mode="json"))
    except Exception as exc:
        return _error_payload(
            "INTERNAL_INSPECTION_ERROR",
            f"Unexpected error inspecting repository: {_safe_exception_detail(exc)}",
            error_kind="internal",
            retryable=True,
            repo_path=str(repo_path),
            is_valid_git_repo=False,
        )


def analyze_git_history(
    repo_path: str,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    max_commits: int = 100,
    use_llm: bool = DEFAULT_ENABLE_LLM,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    detail: str = "complete",
) -> dict[str, Any]:
    """Analyze Git history and code changes between two revisions with AST analysis and optional LLM synthesis."""
    if not isinstance(repo_path, str) or not repo_path.strip():
        return _error_payload(
            "EMPTY_REPO_PATH",
            "Parameter 'repo_path' must be a non-empty directory path.",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            resolved_base_sha="",
            resolved_target_sha="",
            llm_backend_status="error",
        )
    if (
        isinstance(max_commits, bool)
        or not isinstance(max_commits, int)
        or max_commits < 1
        or max_commits > 500
    ):
        return _error_payload(
            "INVALID_MAX_COMMITS",
            "Parameter 'max_commits' must be an integer between 1 and 500.",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            resolved_base_sha="",
            resolved_target_sha="",
            llm_backend_status="error",
        )
    try:
        report = run_git_history_analysis(
            repo_path=repo_path,
            base_ref=str(base_ref or "AUTO"),
            target_ref=str(target_ref or "HEAD"),
            max_commits=max_commits,
            use_llm=bool(use_llm),
            ollama_url=DEFAULT_OLLAMA_BASE_URL,
            ollama_model=str(ollama_model or DEFAULT_OLLAMA_MODEL),
        )
        payload = _attach_error_recovery(report.model_dump(mode="json"))
        if detail == "summary" and payload.get("status") == "ok":
            return DEFAULT_EVIDENCE_STORE.retain(
                "git_history_analysis",
                payload,
                completeness=resolve_completeness(
                    skipped_files=len(payload.get("coverage", {}).get("skipped_files", []) or [])
                ),
            )
        return payload
    except Exception as exc:
        return _error_payload(
            "INTERNAL_ANALYSIS_ERROR",
            f"Unexpected error during Git history analysis: {_safe_exception_detail(exc)}",
            error_kind="internal",
            retryable=True,
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            resolved_base_sha="",
            resolved_target_sha="",
            llm_backend_status="error",
        )


def generate_release_notes(
    repo_path: str,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    release_version: str = "Unreleased",
    audience: str = "developers",
    output_file: str | None = None,
    overwrite: bool = False,
    use_llm: bool = DEFAULT_ENABLE_LLM,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
) -> dict[str, Any]:
    """Generate structured Markdown and JSON release notes backed by verified commit and diff evidence."""
    if not isinstance(repo_path, str) or not repo_path.strip():
        return _error_payload(
            "EMPTY_REPO_PATH",
            "Parameter 'repo_path' must be a non-empty directory path.",
            repo_path=str(repo_path),
            release_version=str(release_version),
            audience="developers",
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            resolved_base_sha="",
            resolved_target_sha="",
            llm_backend_status="error",
        )
    try:
        report = run_release_notes_generation(
            repo_path=repo_path,
            base_ref=str(base_ref or "AUTO"),
            target_ref=str(target_ref or "HEAD"),
            release_version=str(release_version or "Unreleased"),
            audience=str(audience or "developers"),
            output_file=output_file,
            overwrite=bool(overwrite),
            use_llm=bool(use_llm),
            ollama_url=DEFAULT_OLLAMA_BASE_URL,
            ollama_model=str(ollama_model or DEFAULT_OLLAMA_MODEL),
        )
        return _attach_error_recovery(report.model_dump(mode="json"))
    except Exception as exc:
        return _error_payload(
            "INTERNAL_RELEASE_NOTES_ERROR",
            f"Unexpected error generating release notes: {_safe_exception_detail(exc)}",
            error_kind="internal",
            retryable=True,
            repo_path=str(repo_path),
            release_version=str(release_version),
            audience="developers",
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            resolved_base_sha="",
            resolved_target_sha="",
            llm_backend_status="error",
        )


def detect_potential_breaking_changes(
    repo_path: str,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    include_low_confidence: bool = False,
    use_llm: bool = DEFAULT_ENABLE_LLM,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    detail: str = "complete",
) -> dict[str, Any]:
    """Detect potential breaking changes requiring human review with verified evidence and caller impact."""
    if not isinstance(repo_path, str) or not repo_path.strip():
        return _error_payload(
            "EMPTY_REPO_PATH",
            "Parameter 'repo_path' must be a non-empty directory path.",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            resolved_base_sha="",
            resolved_target_sha="",
            llm_backend_status="error",
        )
    try:
        report = run_breaking_change_detection(
            repo_path=repo_path,
            base_ref=str(base_ref or "AUTO"),
            target_ref=str(target_ref or "HEAD"),
            include_low_confidence=bool(include_low_confidence),
            use_llm=bool(use_llm),
            ollama_url=DEFAULT_OLLAMA_BASE_URL,
            ollama_model=str(ollama_model or DEFAULT_OLLAMA_MODEL),
        )
        payload = _attach_error_recovery(report.model_dump(mode="json"))
        if detail == "summary" and payload.get("status") == "ok":
            cov = payload.get("coverage") or {}
            return DEFAULT_EVIDENCE_STORE.retain(
                "breaking_change_report",
                payload,
                completeness=resolve_completeness(
                    skipped_files=len(cov.get("skipped_files", []) or []),
                    unresolved_unknowns=int(cov.get("unresolved_dynamic_calls_count", 0) or 0),
                ),
            )
        return payload
    except Exception as exc:
        return _error_payload(
            "INTERNAL_BREAKING_CHANGE_ERROR",
            f"Unexpected error detecting breaking changes: {_safe_exception_detail(exc)}",
            error_kind="internal",
            retryable=True,
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            resolved_base_sha="",
            resolved_target_sha="",
            llm_backend_status="error",
        )


def analyze_change_graph(
    repo_path: str,
    base_ref: str = "AUTO",
    head_ref: str = "HEAD",
    max_commits: int = 100,
    use_llm: bool = DEFAULT_ENABLE_LLM,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    detail: str = "complete",
) -> dict[str, Any]:
    """Inspect deterministic symbol delta graph, caller blast radius, and commit history across base_ref..head_ref."""
    return analyze_git_history(
        repo_path=repo_path,
        base_ref=base_ref,
        target_ref=head_ref,
        max_commits=max_commits,
        use_llm=use_llm,
        ollama_model=ollama_model,
        detail=detail,
    )


def verify_breaking_and_doc_drift(
    repo_path: str,
    base_ref: str = "AUTO",
    head_ref: str = "HEAD",
    include_low_confidence: bool = False,
    enable_llm_behavioral_pass: bool = DEFAULT_ENABLE_LLM,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    detail: str = "complete",
) -> dict[str, Any]:
    """Verify breaking changes, doc drift, and caller impact across base_ref..head_ref."""
    return detect_potential_breaking_changes(
        repo_path=repo_path,
        base_ref=base_ref,
        target_ref=head_ref,
        include_low_confidence=include_low_confidence,
        use_llm=enable_llm_behavioral_pass,
        ollama_model=ollama_model,
        detail=detail,
    )


def generate_verified_release_brief(
    repo_path: str,
    base_ref: str = "AUTO",
    head_ref: str = "HEAD",
    release_version: str = "Unreleased",
    audience: str = "maintainer_review",
    output_file: str | None = None,
    overwrite: bool = False,
    use_llm: bool = DEFAULT_ENABLE_LLM,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
) -> dict[str, Any]:
    """Generate structured Markdown + JSON release brief backed by verified commit and diff evidence."""
    mapped_audience = (
        "maintainers"
        if audience == "maintainer_review"
        else ("developers" if audience == "public_release_notes" else audience)
    )
    return generate_release_notes(
        repo_path=repo_path,
        base_ref=base_ref,
        target_ref=head_ref,
        release_version=release_version,
        audience=mapped_audience,
        output_file=output_file,
        overwrite=overwrite,
        use_llm=use_llm,
        ollama_model=ollama_model,
    )


def query_code_graph_tool(
    repo_path: str,
    query: str = "",
    depth: int = 2,
    token_budget: int = 2000,
    include_tests: bool = False,
    rebuild: bool = False,
    detail: str = "complete",
) -> dict[str, Any]:
    """Build/load the code knowledge graph and run a token-budgeted query or return graph stats."""
    try:
        cg = DEFAULT_GRAPH_MANAGER.get_or_build(repo_path, rebuild=bool(rebuild))
        if query.strip():
            result = _query_graph_engine(
                cg,
                query,
                depth=depth,
                token_budget=token_budget,
                include_tests=include_tests,
            )
        else:
            result = get_graph_stats(cg)
        if detail == "summary":
            return DEFAULT_EVIDENCE_STORE.retain(
                "code_graph_query",
                result,
                completeness=cg.completeness,
            )
        return result
    except AthenaValidationError as exc:
        return _error_payload(exc.code, exc.message, error_kind="validation")
    except Exception as exc:
        return _error_payload(
            "GRAPH_QUERY_ERROR",
            f"Unexpected error querying code graph: {_safe_exception_detail(exc)}",
            error_kind="internal",
            retryable=True,
        )


def get_repo_map_tool(
    repo_path: str,
    max_chars: int = 2000,
) -> dict[str, Any]:
    """Generate a compact zero-search export map for the repository."""
    try:
        return build_repo_map(repo_path, max_chars=max_chars)
    except AthenaValidationError as exc:
        return _error_payload(exc.code, exc.message, error_kind="validation")
    except Exception as exc:
        return _error_payload(
            "REPO_MAP_ERROR",
            f"Unexpected error building repo map: {_safe_exception_detail(exc)}",
            error_kind="internal",
            retryable=True,
        )


def scan_debt_tool(
    repo_path: str,
    include_todos: bool = False,
    offset: int = 0,
    limit: int | None = None,
) -> dict[str, Any]:
    """Scan repository for `shortcut:` technical debt markers with optional pagination."""
    try:
        return scan_shortcut_debt(
            repo_path,
            include_todos=bool(include_todos),
            offset=offset,
            limit=limit,
        ).model_dump(mode="json")
    except AthenaValidationError as exc:
        return _error_payload(exc.code, exc.message, error_kind="validation")
    except Exception as exc:
        return _error_payload(
            "DEBT_SCAN_ERROR",
            f"Unexpected error scanning debt: {_safe_exception_detail(exc)}",
            error_kind="internal",
            retryable=True,
        )


def inspect_analysis_view_tool(
    evidence_id: str,
    facet: str,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """Inspect a paged slice of a retained evidence bundle."""
    return DEFAULT_EVIDENCE_STORE.inspect_view(
        evidence_id=evidence_id,
        facet=facet,
        offset=offset,
        limit=limit,
    )


def predict_affected_tests_tool(
    repo_path: str,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    offset: int = 0,
    limit: int | None = None,
) -> dict[str, Any]:
    """Select test files impacted by changes between base_ref and target_ref."""
    try:
        return predict_affected_tests(
            repo_path,
            base_ref=base_ref,
            target_ref=target_ref,
            offset=offset,
            limit=limit,
        )
    except AthenaValidationError as exc:
        return _error_payload(exc.code, exc.message, error_kind="validation")
    except Exception as exc:
        return _error_payload(
            "TEST_SELECTION_ERROR",
            f"Unexpected error predicting affected tests: {_safe_exception_detail(exc)}",
            error_kind="internal",
            retryable=True,
        )


def discover_tools_tool(
    query: str = "",
    category: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    """Return matching Athena MCP tools and their hot/cold tier and toolset metadata."""
    q = query.strip().lower()
    cat = category.strip().lower()
    cap = max(1, min(limit, 50))
    matches = [
        item
        for item in _TOOL_CATALOG_METADATA
        if (not cat or item["category"].lower() == cat)
        and (
            not q
            or q in item["name"].lower()
            or q in item["title"].lower()
            or q in item["category"].lower()
            or q in item["summary"].lower()
        )
    ]
    return {
        "status": "ok",
        "total_catalog_tools": len(_TOOL_CATALOG_METADATA),
        "available_toolsets": list(VALID_TOOLSETS),
        "matches": matches[:cap],
    }


def generate_fix_plan_tool(
    repo_path: str,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    apply: bool = False,
    include_review_required: bool = False,
    include_low_confidence: bool = False,
) -> dict[str, Any]:
    """Plan and optionally apply deterministic patches for breaking changes and doc drift."""
    try:
        return generate_fix_plan(
            repo_path=repo_path,
            base_ref=str(base_ref or "AUTO"),
            target_ref=str(target_ref or "HEAD"),
            apply=bool(apply),
            include_review_required=bool(include_review_required),
            include_low_confidence=bool(include_low_confidence),
        ).model_dump(mode="json")
    except AthenaValidationError as exc:
        return _error_payload(exc.code, exc.message, error_kind="validation")
    except Exception as exc:
        return _error_payload(
            "FIX_PLAN_ERROR",
            f"Unexpected error generating fix plan: {_safe_exception_detail(exc)}",
            error_kind="internal",
            retryable=True,
        )


def get_token_savings_report_tool(
    repo_path: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Return persistent local telemetry tracking raw vs compacted token output."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 200:
        return _error_payload(
            "INVALID_LIMIT",
            "Parameter 'limit' must be an integer between 1 and 200.",
            error_kind="validation",
        )
    scope = str(repo_path).strip() if isinstance(repo_path, str) and repo_path.strip() else None
    return read_gain_report(scope, limit=limit)


_READ_ONLY_LOCAL = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_READ_ONLY_LLM = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)
_WRITE_CAPABLE_LOCAL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)
_WRITE_CAPABLE_LLM = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

_TOOL_REGISTRY: tuple[dict[str, Any], ...] = (
    {
        "name": "inspect_repository",
        "title": "Inspect Git Repository",
        "category": "git",
        "tier": "hot",
        "summary": "Inspect repo branches, tags, and dirty state.",
        "description": (
            "Inspect a local Git repository safely (read-only). Returns repository validity, empty/shallow status, "
            "current branch, local branches, tags, working-tree status (staged, unstaged, untracked files), and recent commits."
        ),
        "annotations": _READ_ONLY_LOCAL,
        "fn": inspect_repository,
    },
    {
        "name": "get_repo_map",
        "title": "Get Repository Architecture Map",
        "category": "graph",
        "tier": "hot",
        "summary": "2KB zero-search architectural export map.",
        "description": (
            "Return a compact (<=2000 chars) zero-search architectural export map of shared modules and symbols "
            "in the repository, sanitized against prompt injection."
        ),
        "annotations": _READ_ONLY_LOCAL,
        "fn": get_repo_map_tool,
    },
    {
        "name": "query_code_graph",
        "title": "Query Code Knowledge Graph",
        "category": "graph",
        "tier": "hot",
        "summary": "Trigram+IDF + hub-guarded BFS code graph query.",
        "description": (
            "Query Athena's persistent, zero-LLM code knowledge graph using trigram+IDF scoring and hub-guarded BFS "
            "(strictly bounded by token_budget). Set detail='summary' to retain the full graph in-session and on disk."
        ),
        "annotations": _READ_ONLY_LOCAL,
        "fn": query_code_graph_tool,
    },
    {
        "name": "detect_potential_breaking_changes",
        "title": "Detect Potential Breaking Changes",
        "category": "analysis",
        "tier": "hot",
        "summary": "AST signature diffing & caller blast radius.",
        "description": (
            "Detect potential breaking changes requiring human review between base_ref and target_ref. "
            "Uses deterministic AST signature diffing (removed symbols, incompatible parameter changes, return types, "
            "decorators, raised exceptions, base classes, recursive function bugs), downstream caller blast radius, doc drift, and optional LLM review notes."
        ),
        "annotations": _READ_ONLY_LLM,
        "fn": detect_potential_breaking_changes,
    },
    {
        "name": "predict_affected_tests",
        "title": "Predict Affected Tests",
        "category": "testing",
        "tier": "hot",
        "summary": "Select pytest/Playwright/unit tests impacted by diff.",
        "description": (
            "Predict which unit or e2e test files (pytest, Playwright .spec.ts, etc.) should run "
            "based on changed files and AST symbols between base_ref and target_ref, with bounded pagination."
        ),
        "annotations": _READ_ONLY_LOCAL,
        "fn": predict_affected_tests_tool,
    },
    {
        "name": "inspect_analysis_view",
        "title": "Inspect Retained Evidence View",
        "category": "evidence",
        "tier": "hot",
        "summary": "Page through retained ev_<sha256> bundles.",
        "description": (
            "Page through a retained evidence bundle (`ev_<sha256>`) by facet, offset, and limit "
            "across sessions without overflowing the context window."
        ),
        "annotations": _READ_ONLY_LOCAL,
        "fn": inspect_analysis_view_tool,
    },
    {
        "name": "analyze_git_history",
        "title": "Analyze Git History",
        "category": "analysis",
        "tier": "cold",
        "summary": "Group commits/diffs into evidence-backed stories.",
        "description": (
            "Analyze Git commit history and code diffs between base_ref (e.g., tag, branch, SHA, or 'AUTO') "
            "and target_ref (e.g., 'HEAD', branch, tag, or 'WORKING_TREE'). Deterministically groups changes into "
            "logical stories with verified evidence records, with optional qwen2.5-coder:7b or gemma:latest semantic synthesis when use_llm=True."
        ),
        "annotations": _READ_ONLY_LLM,
        "fn": analyze_git_history,
    },
    {
        "name": "generate_release_notes",
        "title": "Generate Release Notes",
        "category": "release",
        "tier": "cold",
        "summary": "Render audience-tailored Markdown release notes.",
        "description": (
            "Generate structured, evidence-backed release notes for a revision range tailored to an audience "
            "('end_users', 'developers', 'maintainers', 'clients'). Operates deterministically without an LLM, "
            "with optional qwen2.5-coder:7b or gemma:latest enhancement when use_llm=True. Never overwrites files without overwrite=True."
        ),
        "annotations": _WRITE_CAPABLE_LLM,
        "fn": generate_release_notes,
    },
    {
        "name": "scan_debt",
        "title": "Scan Shortcut Technical Debt",
        "category": "debt",
        "tier": "cold",
        "summary": "Scan `shortcut:` markers bound to AST symbols.",
        "description": (
            "Scan repository source files for `shortcut: <limit>, <when to upgrade>` debt markers "
            "(and optional TODO/FIXME) bound to AST enclosing symbols with bounded offset/limit pagination."
        ),
        "annotations": _READ_ONLY_LOCAL,
        "fn": scan_debt_tool,
    },
    {
        "name": "analyze_change_graph",
        "title": "Analyze Change Graph",
        "category": "analysis",
        "tier": "cold",
        "summary": "Alias for analyze_git_history.",
        "description": (
            "Analyze Git commit history, multi-language AST symbol deltas, "
            "and caller blast radius across revisions base_ref..head_ref."
        ),
        "annotations": _READ_ONLY_LLM,
        "fn": analyze_change_graph,
    },
    {
        "name": "verify_breaking_and_doc_drift",
        "title": "Verify Breaking Changes and Doc Drift",
        "category": "analysis",
        "tier": "cold",
        "summary": "Alias for detect_potential_breaking_changes.",
        "description": (
            "Verify whether any public API broke without Conventional Commit markers, "
            "whether callers broke, whether docs drifted, and runtime contract changes across base_ref..head_ref."
        ),
        "annotations": _READ_ONLY_LLM,
        "fn": verify_breaking_and_doc_drift,
    },
    {
        "name": "generate_verified_release_brief",
        "title": "Generate Verified Release Brief",
        "category": "release",
        "tier": "cold",
        "summary": "Alias for generate_release_notes.",
        "description": (
            "Render an evidence-anchored release and verification brief "
            "where every finding cites [ev_XXX: file:Lstart-Lend @ sha]."
        ),
        "annotations": _WRITE_CAPABLE_LLM,
        "fn": generate_verified_release_brief,
    },
    {
        "name": "generate_fix_plan",
        "title": "Generate Breaking-Change Fix Plan",
        "category": "analysis",
        "tier": "hot",
        "summary": "Deterministic dry-run diffs & safe remediation patches.",
        "description": (
            "Generate deterministic remediation patches (`safe` vs `review_required`) with unified diffs for broken "
            "Python callers, recursion bugs, unguarded None defaults, stale docstrings, and migration guides. Dry-run by default."
        ),
        "annotations": _WRITE_CAPABLE_LOCAL,
        "fn": generate_fix_plan_tool,
    },
    {
        "name": "get_token_savings_report",
        "title": "Get Token Savings Ledger",
        "category": "meta",
        "tier": "hot",
        "summary": "Inspect measured raw vs compacted context savings.",
        "description": (
            "Read Athena's local append-only token-savings ledger (`athena gain`), aggregated globally or scoped to a repository."
        ),
        "annotations": _READ_ONLY_LOCAL,
        "fn": get_token_savings_report_tool,
    },
    {
        "name": "discover_tools",
        "title": "Discover Athena MCP Tools",
        "category": "meta",
        "tier": "hot",
        "summary": "Search Athena's hot/cold MCP tool catalog.",
        "description": "Search Athena's MCP tool catalog by keyword, category, or toolset tier.",
        "annotations": _READ_ONLY_LOCAL,
        "fn": discover_tools_tool,
    },
)

_TOOL_CATALOG_METADATA: tuple[dict[str, Any], ...] = tuple(
    {
        "name": spec["name"],
        "title": spec["title"],
        "category": spec["category"],
        "tier": spec["tier"],
        "summary": spec["summary"],
    }
    for spec in _TOOL_REGISTRY
)


def _call_with_supported_kwargs(
    decorator_factory: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Invoke an MCP SDK decorator cleanly across MCP 1.x and 2.x signatures."""
    params = inspect.signature(decorator_factory).parameters
    filtered = {k: v for k, v in kwargs.items() if k in params and v is not None}
    return decorator_factory(*args, **filtered)


def _register_resources(
    server: MCPServer,
    *,
    active_toolsets: tuple[str, ...],
    read_only: bool,
    registered_tools: list[str],
) -> None:
    """Register standard Athena MCP resources and URI templates."""

    @_call_with_supported_kwargs(
        server.resource,
        "athena://server/capabilities",
        name="server_capabilities",
        title="Athena Server Capabilities",
        description="Runtime metadata, active toolsets, read-only policy, and Rust kernel status.",
        mime_type="application/json",
    )
    def server_capabilities_resource() -> str:
        try:
            mcp_version = importlib_metadata.version("mcp")
        except importlib_metadata.PackageNotFoundError:
            mcp_version = "unknown"
        payload = {
            "server": "athena-mcp",
            "version": __version__,
            "mcp_sdk_version": mcp_version,
            "active_toolsets": list(active_toolsets),
            "read_only": read_only,
            "registered_tools": list(registered_tools),
            "rust_acceleration": get_rust_acceleration_status(),
            "treesitter": get_treesitter_status(),
            "retained_evidence_count": len(DEFAULT_EVIDENCE_STORE.list_retained()),
        }
        return json.dumps(payload, indent=2)

    @_call_with_supported_kwargs(
        server.resource,
        "athena://gain/summary",
        name="token_savings_summary",
        title="Athena Token Savings Summary",
        description="Aggregated raw vs compacted character/token savings recorded across Athena runs.",
        mime_type="application/json",
    )
    def token_savings_summary_resource() -> str:
        return json.dumps(read_gain_report(), indent=2)

    @_call_with_supported_kwargs(
        server.resource,
        "athena://repo/map",
        name="workspace_repo_map",
        title="Workspace Architectural Export Map",
        description="Compact zero-search architectural export map of the current working directory.",
        mime_type="text/plain",
    )
    def workspace_repo_map_resource() -> str:
        try:
            res = build_repo_map(Path.cwd(), max_chars=2000)
            return str(res.get("map_text", ""))
        except AthenaValidationError as exc:
            return f"Athena workspace map unavailable ({exc.code}): {exc.message}"

    @_call_with_supported_kwargs(
        server.resource,
        "athena://evidence/recent",
        name="recent_evidence_bundles",
        title="Recent Retained Evidence Bundles",
        description="List of evidence bundles (`ev_<sha256>`) retained across memory and disk.",
        mime_type="application/json",
    )
    def recent_evidence_resource() -> str:
        return json.dumps(
            {
                "status": "ok",
                "bundles": DEFAULT_EVIDENCE_STORE.list_retained(),
            },
            indent=2,
        )

    @_call_with_supported_kwargs(
        server.resource,
        "athena://evidence/{evidence_id}",
        name="evidence_bundle_detail",
        title="Retained Evidence Bundle Facet Index",
        description="Metadata and facet counts for a specific `ev_<sha256>` evidence bundle.",
        mime_type="application/json",
    )
    def evidence_bundle_resource(evidence_id: str) -> str:
        bundles = {b["evidence_id"]: b for b in DEFAULT_EVIDENCE_STORE.list_retained()}
        if evidence_id in bundles:
            return json.dumps({"status": "ok", **bundles[evidence_id]}, indent=2)
        if not DEFAULT_EVIDENCE_STORE.has(evidence_id):
            return json.dumps(
                _error_payload(
                    "EVIDENCE_NOT_FOUND",
                    f"No retained evidence found for '{evidence_id}'.",
                    error_kind="not_found",
                    retryable=True,
                ),
                indent=2,
            )
        refreshed = {b["evidence_id"]: b for b in DEFAULT_EVIDENCE_STORE.list_retained()}
        return json.dumps({"status": "ok", **refreshed.get(evidence_id, {"evidence_id": evidence_id})}, indent=2)


def _register_prompts(server: MCPServer) -> None:
    """Register workflow prompts guiding LLM clients through Athena's deterministic checks."""

    @_call_with_supported_kwargs(
        server.prompt,
        name="pre_merge_audit",
        title="Pre-Merge Breaking Change & Test Audit",
        description="Structured checklist to check breaking changes, callers, affected tests, and evidence.",
    )
    def pre_merge_audit_prompt(
        repo_path: str = ".",
        base_ref: str = "AUTO",
        target_ref: str = "HEAD",
    ) -> str:
        return (
            f"Run a deterministic pre-merge verification on `{repo_path}` (`{base_ref}..{target_ref}`):\n"
            "1. Call `inspect_repository(repo_path)` to confirm clean refs and repo status.\n"
            "2. Call `detect_potential_breaking_changes(repo_path, base_ref, target_ref, detail='summary')` "
            "and inspect `potential_breaking_changes` via `inspect_analysis_view` if non-empty.\n"
            "3. Call `predict_affected_tests(repo_path, base_ref, target_ref)` to list targeted test files.\n"
            "4. Summarize verified findings citing evidence IDs and file:line locations."
        )

    @_call_with_supported_kwargs(
        server.prompt,
        name="release_readiness_review",
        title="Release Readiness Review",
        description="End-to-end release verification covering history stories, breaking APIs, debt, and notes.",
    )
    def release_readiness_review_prompt(
        repo_path: str = ".",
        base_ref: str = "AUTO",
        target_ref: str = "HEAD",
        release_version: str = "Unreleased",
    ) -> str:
        return (
            f"Prepare release `{release_version}` for `{repo_path}` (`{base_ref}..{target_ref}`):\n"
            "1. Run `analyze_git_history(..., detail='summary')` and `detect_potential_breaking_changes(..., detail='summary')`.\n"
            "2. Check `scan_debt(repo_path)` for `shortcut:` markers missing upgrade triggers.\n"
            "3. Verify required SemVer bump matches detected breaking changes before drafting `generate_release_notes`."
        )

    @_call_with_supported_kwargs(
        server.prompt,
        name="codebase_onboarding",
        title="Codebase Onboarding Orientation",
        description="Zero-search architectural orientation via Athena map, code graph, and technical debt.",
    )
    def codebase_onboarding_prompt(repo_path: str = ".", focus: str = "") -> str:
        focus_line = f" focusing on `{focus}`" if focus.strip() else ""
        return (
            f"Map `{repo_path}`{focus_line} without blind grep loops:\n"
            "1. Call `get_repo_map(repo_path)` for the top-level architectural export map.\n"
            "2. Call `query_code_graph(repo_path, query=focus)` to trace god nodes and tightest call communities.\n"
            "3. Call `scan_debt(repo_path, limit=25)` to surface known `# shortcut:` constraints."
        )


def create_mcp_server(
    *,
    toolsets: str | Sequence[str] | None = None,
    read_only: bool = False,
) -> MCPServer:
    """Create a configured Athena MCPServer with optional toolset & read-only scoping."""
    active_toolsets = parse_toolsets(toolsets)
    if _MCP_SUPPORTS_VERSION:
        server = MCPServer(name="athena-mcp", version=__version__, instructions=_MCP_INSTRUCTIONS)
    else:  # pragma: no cover - exercised in the MCP 1.x compatibility environment
        server = MCPServer(name="athena-mcp", instructions=_MCP_INSTRUCTIONS)

    registered_tools: list[str] = []
    for spec in _TOOL_REGISTRY:
        if spec["category"] not in active_toolsets:
            continue
        annotations: ToolAnnotations = spec["annotations"]
        is_read_only_tool = bool(annotations.model_dump(by_alias=True).get("readOnlyHint"))
        if read_only and not is_read_only_tool:
            continue
        decorator = _call_with_supported_kwargs(
            server.tool,
            name=spec["name"],
            title=spec["title"],
            description=spec["description"],
            annotations=annotations,
        )
        decorator(spec["fn"])
        registered_tools.append(spec["name"])

    _register_resources(
        server,
        active_toolsets=active_toolsets,
        read_only=bool(read_only),
        registered_tools=registered_tools,
    )
    _register_prompts(server)

    setattr(server, "_athena_toolsets", active_toolsets)
    setattr(server, "_athena_read_only", bool(read_only))
    setattr(server, "_athena_registered_tools", tuple(registered_tools))
    return server


mcp_app = create_mcp_server()


def run_mcp_server(
    *,
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8765,
    toolsets: str | Sequence[str] | None = None,
    read_only: bool = False,
    allow_remote: bool = False,
) -> None:
    """Start the Athena MCP server over stdio or loopback-guarded streamable-http."""
    if transport not in VALID_TRANSPORTS:
        raise AthenaValidationError(
            "INVALID_TRANSPORT",
            f"Unsupported transport '{transport}'. Choose one of: {', '.join(VALID_TRANSPORTS)}.",
        )
    if isinstance(port, bool) or not isinstance(port, int) or port < 1 or port > 65535:
        raise AthenaValidationError("INVALID_PORT", f"port must be in 1..65535 (got {port!r}).")

    clean_host = (host or "127.0.0.1").strip()
    if transport == "streamable-http" and not allow_remote and clean_host not in _LOOPBACK_HOSTS:
        raise AthenaValidationError(
            "REMOTE_BIND_BLOCKED",
            f"Refusing non-loopback streamable-http host '{clean_host}' without allow_remote=True.",
        )

    server = (
        mcp_app
        if toolsets is None and not read_only
        else create_mcp_server(toolsets=toolsets, read_only=read_only)
    )

    if transport == "stdio":
        server.run(transport="stdio")
        return

    run_http = getattr(server, "run_streamable_http_async", None)
    http_params = inspect.signature(run_http).parameters if run_http is not None else {}
    if "host" in http_params and "port" in http_params:
        server.run(transport="streamable-http", host=clean_host, port=port)
        return

    # Fallback for MCP 1.x FastMCP where host/port live on settings
    settings = getattr(server, "settings", None)
    if settings is not None:
        if hasattr(settings, "host"):
            setattr(settings, "host", clean_host)
        if hasattr(settings, "port"):
            setattr(settings, "port", port)
    server.run(transport="streamable-http")


def run_mcp_stdio_server() -> None:
    """Start the Athena MCP server over stdio transport."""
    run_mcp_server(transport="stdio")


main = run_mcp_stdio_server


if __name__ == "__main__":
    run_mcp_stdio_server()
