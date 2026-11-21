"""Athena Model Context Protocol (MCP) Server Implementation."""

from __future__ import annotations

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
from athena.graph_query import get_god_nodes, get_graph_stats, query_code_graph as _query_graph_engine, shortest_path_between
from athena.graph_store import DEFAULT_GRAPH_MANAGER
from athena.ollama_engine import DEFAULT_ENABLE_LLM, DEFAULT_OLLAMA_BASE_URL, DEFAULT_OLLAMA_MODEL
from athena.release_notes import (
    run_breaking_change_detection,
    run_git_history_analysis,
    run_release_notes_generation,
)
from athena.repo_map import build_repo_map
from athena.security import redact_secrets


def _safe_exception_detail(exc: Exception) -> str:
    """Return an exception summary with credentials removed before MCP serialization."""
    return redact_secrets(f"{type(exc).__name__}: {exc}")


_MCP_INSTRUCTIONS = (
        f"Athena v{__version__} is an offline-capable, local-first multi-language Git intelligence and AST change analysis MCP server. "
        "Athena is created and maintained by Aaryan Rawat. "
        "All core operations (Git diff inspection, Python AST analysis, TypeScript/JS, C/C++, Go, Rust, Java, C#, Ruby, and PHP "
        "structural signature diffing, caller blast-radius scanning, doc drift detection, evidence verification, release notes, and "
        "breaking change detection) operate deterministically without requiring any LLM. Local Ollama (gemma:latest and qwen2.5-coder:7b) "
        "is an optional enhancement when use_llm=True is explicitly enabled. Analysis operations are read-only; release tools write "
        "only when an output_file is explicitly supplied."
)

# MCP 1.x FastMCP does not accept the 2.x `version` constructor argument.
# Keep the supported 1.x fallback usable while retaining explicit version metadata
# on MCP 2.x servers.
if _MCP_SUPPORTS_VERSION:
    mcp_app = MCPServer(name="athena-mcp", version=__version__, instructions=_MCP_INSTRUCTIONS)
else:  # pragma: no cover - exercised in the MCP 1.x compatibility environment
    mcp_app = MCPServer(name="athena-mcp", instructions=_MCP_INSTRUCTIONS)


@mcp_app.tool(
    name="inspect_repository",
    description=(
        "Inspect a local Git repository safely (read-only). Returns repository validity, empty/shallow status, "
        "current branch, local branches, tags, working-tree status (staged, unstaged, untracked files), and recent commits."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def inspect_repository(
    repo_path: str,
    max_recent_commits: int = 10,
) -> dict[str, Any]:
    """Inspect a local Git repository and return a structured RepositoryStatusReport."""
    if not isinstance(repo_path, str) or not repo_path.strip():
        return {
            "status": "error",
            "repo_path": str(repo_path),
            "is_valid_git_repo": False,
            "error_code": "EMPTY_REPO_PATH",
            "error_message": "Parameter 'repo_path' must be a non-empty directory path.",
        }
    if isinstance(max_recent_commits, bool) or not isinstance(max_recent_commits, int) or max_recent_commits < 1 or max_recent_commits > 100:
        return {
            "status": "error",
            "repo_path": repo_path,
            "is_valid_git_repo": False,
            "error_code": "INVALID_MAX_COMMITS",
            "error_message": "Parameter 'max_recent_commits' must be an integer between 1 and 100.",
        }
    try:
        report = inspect_repository_state(repo_path_input=repo_path, max_recent_commits=max_recent_commits)
        return report.model_dump(mode="json")
    except Exception as exc:
        return {
            "status": "error",
            "repo_path": str(repo_path),
            "is_valid_git_repo": False,
            "error_code": "INTERNAL_INSPECTION_ERROR",
            "error_message": f"Unexpected error inspecting repository: {_safe_exception_detail(exc)}",
        }


@mcp_app.tool(
    name="analyze_git_history",
    description=(
        "Analyze Git commit history and code diffs between base_ref (e.g., tag, branch, SHA, or 'AUTO') "
        "and target_ref (e.g., 'HEAD', branch, tag, or 'WORKING_TREE'). Deterministically groups changes into "
        "logical stories with verified evidence records, with optional qwen2.5-coder:7b or gemma:latest semantic synthesis when use_llm=True."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
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
        return {
            "status": "error",
            "repo_path": str(repo_path),
            "base_ref": str(base_ref),
            "target_ref": str(target_ref),
            "resolved_base_sha": "",
            "resolved_target_sha": "",
            "llm_backend_status": "error",
            "error_code": "EMPTY_REPO_PATH",
            "error_message": "Parameter 'repo_path' must be a non-empty directory path.",
        }
    if isinstance(max_commits, bool) or not isinstance(max_commits, int) or max_commits < 1 or max_commits > 500:
        return {
            "status": "error",
            "repo_path": str(repo_path),
            "base_ref": str(base_ref),
            "target_ref": str(target_ref),
            "resolved_base_sha": "",
            "resolved_target_sha": "",
            "llm_backend_status": "error",
            "error_code": "INVALID_MAX_COMMITS",
            "error_message": "Parameter 'max_commits' must be an integer between 1 and 500.",
        }
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
        payload = report.model_dump(mode="json")
        if detail == "summary":
            return DEFAULT_EVIDENCE_STORE.retain(
                "git_history_analysis",
                payload,
                completeness=resolve_completeness(
                    skipped_files=len(payload.get("coverage", {}).get("skipped_files", []) or [])
                ),
            )
        return payload
    except Exception as exc:
        return {
            "status": "error",
            "repo_path": str(repo_path),
            "base_ref": str(base_ref),
            "target_ref": str(target_ref),
            "resolved_base_sha": "",
            "resolved_target_sha": "",
            "llm_backend_status": "error",
            "error_code": "INTERNAL_ANALYSIS_ERROR",
            "error_message": f"Unexpected error during Git history analysis: {_safe_exception_detail(exc)}",
        }


@mcp_app.tool(
    name="generate_release_notes",
    description=(
        "Generate structured, evidence-backed release notes for a revision range tailored to an audience "
        "('end_users', 'developers', 'maintainers', 'clients'). Operates deterministically without an LLM, "
        "with optional qwen2.5-coder:7b or gemma:latest enhancement when use_llm=True. Never overwrites files without overwrite=True."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=True,
    ),
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
        return {
            "status": "error",
            "repo_path": str(repo_path),
            "release_version": str(release_version),
            "audience": "developers",
            "base_ref": str(base_ref),
            "target_ref": str(target_ref),
            "resolved_base_sha": "",
            "resolved_target_sha": "",
            "llm_backend_status": "error",
            "error_code": "EMPTY_REPO_PATH",
            "error_message": "Parameter 'repo_path' must be a non-empty directory path.",
        }
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
        return report.model_dump(mode="json")
    except Exception as exc:
        return {
            "status": "error",
            "repo_path": str(repo_path),
            "release_version": str(release_version),
            "audience": "developers",
            "base_ref": str(base_ref),
            "target_ref": str(target_ref),
            "resolved_base_sha": "",
            "resolved_target_sha": "",
            "llm_backend_status": "error",
            "error_code": "INTERNAL_RELEASE_NOTES_ERROR",
            "error_message": f"Unexpected error generating release notes: {_safe_exception_detail(exc)}",
        }


@mcp_app.tool(
    name="detect_potential_breaking_changes",
    description=(
        "Detect potential breaking changes requiring human review between base_ref and target_ref. "
        "Uses deterministic AST signature diffing (removed symbols, incompatible parameter changes, return types, "
        "decorators, raised exceptions, base classes, recursive function bugs), downstream caller blast radius, doc drift, and optional LLM review notes."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
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
        return {
            "status": "error",
            "repo_path": str(repo_path),
            "base_ref": str(base_ref),
            "target_ref": str(target_ref),
            "resolved_base_sha": "",
            "resolved_target_sha": "",
            "llm_backend_status": "error",
            "error_code": "EMPTY_REPO_PATH",
            "error_message": "Parameter 'repo_path' must be a non-empty directory path.",
        }
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
        payload = report.model_dump(mode="json")
        if detail == "summary":
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
        return {
            "status": "error",
            "repo_path": str(repo_path),
            "base_ref": str(base_ref),
            "target_ref": str(target_ref),
            "resolved_base_sha": "",
            "resolved_target_sha": "",
            "llm_backend_status": "error",
            "error_code": "INTERNAL_BREAKING_CHANGE_ERROR",
            "error_message": f"Unexpected error detecting breaking changes: {_safe_exception_detail(exc)}",
        }


@mcp_app.tool(
    name="analyze_change_graph",
    description=(
        "Analyze Git commit history, multi-language AST symbol deltas, "
        "and caller blast radius across revisions base_ref..head_ref."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def analyze_change_graph(
    repo_path: str,
    base_ref: str = "AUTO",
    head_ref: str = "HEAD",
    max_commits: int = 100,
    use_llm: bool = DEFAULT_ENABLE_LLM,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
) -> dict[str, Any]:
    """Inspect deterministic symbol delta graph, caller blast radius, and commit history across base_ref..head_ref."""
    return analyze_git_history(
        repo_path=repo_path,
        base_ref=base_ref,
        target_ref=head_ref,
        max_commits=max_commits,
        use_llm=use_llm,
        ollama_model=ollama_model,
    )


@mcp_app.tool(
    name="verify_breaking_and_doc_drift",
    description=(
        "Verify whether any public API broke without Conventional Commit markers, "
        "whether callers broke, whether docs drifted, and runtime contract changes across base_ref..head_ref."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def verify_breaking_and_doc_drift(
    repo_path: str,
    base_ref: str = "AUTO",
    head_ref: str = "HEAD",
    include_low_confidence: bool = False,
    enable_llm_behavioral_pass: bool = DEFAULT_ENABLE_LLM,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
) -> dict[str, Any]:
    """Verify breaking changes, doc drift, and caller impact across base_ref..head_ref."""
    return detect_potential_breaking_changes(
        repo_path=repo_path,
        base_ref=base_ref,
        target_ref=head_ref,
        include_low_confidence=include_low_confidence,
        use_llm=enable_llm_behavioral_pass,
        ollama_model=ollama_model,
    )


@mcp_app.tool(
    name="generate_verified_release_brief",
    description=(
        "Render an evidence-anchored release and verification brief "
        "where every finding cites [ev_XXX: file:Lstart-Lend @ sha]."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=True,
    ),
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
    mapped_audience = "maintainers" if audience == "maintainer_review" else (
        "developers" if audience == "public_release_notes" else audience
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


@mcp_app.tool(
    name="query_code_graph",
    description=(
        "Query Athena's persistent, zero-LLM code knowledge graph using trigram+IDF scoring and hub-guarded BFS "
        "(strictly bounded by token_budget). Set detail='summary' to retain the full graph in-session."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
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
    except Exception as exc:
        return {
            "status": "error",
            "error_code": "GRAPH_QUERY_ERROR",
            "error_message": f"Unexpected error querying code graph: {_safe_exception_detail(exc)}",
        }


@mcp_app.tool(
    name="get_repo_map",
    description=(
        "Return a compact (<=2000 chars) zero-search architectural export map of shared modules and symbols "
        "in the repository, sanitized against prompt injection."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def get_repo_map_tool(
    repo_path: str,
    max_chars: int = 2000,
) -> dict[str, Any]:
    """Generate a compact zero-search export map for the repository."""
    try:
        return build_repo_map(repo_path, max_chars=max_chars)
    except Exception as exc:
        return {
            "status": "error",
            "error_code": "REPO_MAP_ERROR",
            "error_message": f"Unexpected error building repo map: {_safe_exception_detail(exc)}",
        }


@mcp_app.tool(
    name="scan_debt",
    description=(
        "Scan repository source files for `shortcut: <limit>, <when to upgrade>` debt markers "
        "(and optional TODO/FIXME) bound to AST enclosing symbols."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def scan_debt_tool(
    repo_path: str,
    include_todos: bool = False,
) -> dict[str, Any]:
    """Scan repository for `shortcut:` technical debt markers."""
    try:
        return scan_shortcut_debt(repo_path, include_todos=bool(include_todos)).model_dump(mode="json")
    except Exception as exc:
        return {
            "status": "error",
            "error_code": "DEBT_SCAN_ERROR",
            "error_message": f"Unexpected error scanning debt: {_safe_exception_detail(exc)}",
        }


@mcp_app.tool(
    name="inspect_analysis_view",
    description=(
        "Page through a retained evidence bundle (`ev_<sha256>`) by facet, offset, and limit "
        "without overflowing the context window."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
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


_TOOL_CATALOG_METADATA: tuple[dict[str, Any], ...] = (
    {"name": "inspect_repository", "category": "git", "tier": "hot", "summary": "Inspect repo branches, tags, and dirty state."},
    {"name": "get_repo_map", "category": "graph", "tier": "hot", "summary": "2KB zero-search architectural export map."},
    {"name": "query_code_graph", "category": "graph", "tier": "hot", "summary": "Trigram+IDF + hub-guarded BFS code graph query."},
    {"name": "detect_potential_breaking_changes", "category": "analysis", "tier": "hot", "summary": "AST signature diffing & caller blast radius."},
    {"name": "inspect_analysis_view", "category": "evidence", "tier": "hot", "summary": "Page through retained ev_<sha256> bundles."},
    {"name": "analyze_git_history", "category": "analysis", "tier": "cold", "summary": "Group commits/diffs into evidence-backed stories."},
    {"name": "generate_release_notes", "category": "release", "tier": "cold", "summary": "Render audience-tailored Markdown release notes."},
    {"name": "scan_debt", "category": "debt", "tier": "cold", "summary": "Scan `shortcut:` markers bound to AST symbols."},
    {"name": "analyze_change_graph", "category": "analysis", "tier": "cold", "summary": "Alias for analyze_git_history."},
    {"name": "verify_breaking_and_doc_drift", "category": "analysis", "tier": "cold", "summary": "Alias for detect_potential_breaking_changes."},
    {"name": "generate_verified_release_brief", "category": "release", "tier": "cold", "summary": "Alias for generate_release_notes."},
    {"name": "discover_tools", "category": "meta", "tier": "hot", "summary": "Search Athena's hot/cold MCP tool catalog."},
)


@mcp_app.tool(
    name="discover_tools",
    description="Search Athena's MCP tool catalog by keyword or category (rea-style progressive discovery).",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def discover_tools_tool(
    query: str = "",
    limit: int = 10,
) -> dict[str, Any]:
    """Return matching Athena MCP tools and their hot/cold tier metadata."""
    q = query.strip().lower()
    cap = max(1, min(limit, 50))
    matches = [
        item
        for item in _TOOL_CATALOG_METADATA
        if not q or q in item["name"].lower() or q in item["category"].lower() or q in item["summary"].lower()
    ]
    return {
        "status": "ok",
        "total_catalog_tools": len(_TOOL_CATALOG_METADATA),
        "matches": matches[:cap],
    }


def run_mcp_stdio_server() -> None:
    """Start the Athena MCP server over stdio transport."""
    mcp_app.run(transport="stdio")


main = run_mcp_stdio_server


if __name__ == "__main__":
    run_mcp_stdio_server()


