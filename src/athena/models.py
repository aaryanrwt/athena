"""Structured Pydantic v2 data models for Athena's Git analysis, evidence records, and MCP tools."""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


AudienceType = Literal["end_users", "developers", "maintainers", "clients"]
ConfidenceLevel = Literal["high", "medium", "low"]
ChangeCategory = Literal[
    "feature",
    "improvement",
    "bug_fix",
    "refactoring",
    "breaking_change",
    "docs_or_tests",
]


class LineSpan(BaseModel):
    """Explicit 1-indexed line span in either the base or target file."""

    start_line: int = Field(ge=1, description="1-indexed inclusive start line.")
    end_line: int = Field(ge=1, description="1-indexed inclusive end line.")


class EvidenceRecord(BaseModel):
    """Ground-truth evidence derived directly from Git commits, diffs, and ASTs."""

    evidence_id: str = Field(
        description="Deterministic evidence identifier (e.g., ev_001).",
    )
    commit_hash: str = Field(
        description="Actual Git commit SHA (or 'WORKING_TREE' for uncommitted changes)."
    )
    commit_message: str = Field(
        default="",
        description="First-line subject of the commit where this change was observed.",
    )
    file_path: str = Field(
        description="Repository-relative POSIX path of the changed or referenced file."
    )
    base_line_span: LineSpan | None = Field(
        default=None,
        description="1-indexed line numbers in the base revision file, if applicable.",
    )
    target_line_span: LineSpan | None = Field(
        default=None,
        description="1-indexed line numbers in the target revision file, if applicable.",
    )
    diff_hunk_header: str = Field(
        default="",
        description="Exact unified diff @@ header or AST diff header.",
    )
    diff_excerpt: str = Field(
        default="",
        description="Secret-redacted, bounded diff or source excerpt supporting the finding.",
    )
    symbol_name: str | None = Field(
        default=None,
        description="AST function, class, method, or interface symbol name if identified.",
    )
    reason_supports_finding: str = Field(
        description="Concrete explanation of why this Git/AST evidence supports the finding."
    )
    confidence: ConfidenceLevel = Field(
        default="high",
        description="Epistemic confidence level for this evidence record.",
    )
    uncertainty_note: str | None = Field(
        default=None,
        description="Explicit note when static or diff evidence is partial and requires human verification.",
    )


class CommitSummaryItem(BaseModel):
    """Metadata for a single Git commit extracted deterministically."""

    commit_hash: str
    short_hash: str
    author_name: str
    author_email: str
    authored_date: str
    subject: str
    body: str = ""
    changed_files: list[str] = Field(default_factory=list)
    insertions: int = 0
    deletions: int = 0
    conventional_type: str | None = None
    conventional_scope: str | None = None
    declares_breaking_in_message: bool = False


class SymbolSignatureChange(BaseModel):
    """Deterministic AST/signature comparison between base and target revisions."""

    file_path: str
    symbol_name: str
    symbol_kind: Literal["function", "async_function", "method", "class", "interface", "enum", "constant"]
    change_kind: Literal[
        "added",
        "removed",
        "signature_changed",
        "return_type_changed",
        "decorator_changed",
        "base_class_changed",
        "exception_raised_added",
        "behavior_changed",
    ]
    old_signature: str | None = None
    new_signature: str | None = None
    is_breaking_candidate: bool = False
    is_public_api_export: bool = False
    public_api_exposure_reason: str = ""
    severity: Literal["high", "medium", "low"] = "medium"
    details: str = ""
    base_line_span: LineSpan | None = None
    target_line_span: LineSpan | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class CallerImpactItem(BaseModel):
    """Cross-file or intra-file reference to a mutated symbol."""

    caller_file: str
    caller_symbol: str
    enclosing_symbol: str | None = None
    line_number: int
    call_snippet: str
    resolution_confidence: Literal["exact_ast", "heuristic_name_match"] = "exact_ast"
    arity_mismatch_detected: bool = False
    mismatch_details: str = ""


class UnresolvedDynamicCallItem(BaseModel):
    """Dynamic dispatch, reflection, or eval pattern that static AST analysis cannot fully resolve."""

    file_path: str
    line_number: int
    enclosing_symbol: str | None = None
    pattern_kind: Literal[
        "getattr_reflection",
        "globals_locals_lookup",
        "eval_exec_dynamic",
        "importlib_dynamic",
        "ts_bracket_dispatch",
        "kwargs_passthrough",
    ]
    snippet: str
    referenced_symbol_hint: str | None = None
    risk_explanation: str


class AnalysisCoverageReport(BaseModel):
    """Explicit static analysis coverage and confidence boundary metrics for CI and PR review."""

    total_repo_files_discovered: int = 0
    total_code_files_eligible: int = 0
    files_parsed_successfully: int = 0
    files_skipped_or_unparseable: int = 0
    static_parse_coverage_pct: float = 100.0
    exact_ast_callers_count: int = 0
    heuristic_callers_count: int = 0
    callers_with_arity_mismatch_count: int = 0
    unresolved_dynamic_calls_count: int = 0
    public_api_exports_modified_count: int = 0
    overall_blast_radius_confidence: ConfidenceLevel = "high"
    confidence_rationale: str = (
        "100% of eligible internal source files parsed statically with zero unresolved dynamic calls."
    )


class DocDriftItem(BaseModel):
    """Stale documentation or README reference to a removed or signature-changed symbol."""

    doc_file: str
    line_number: int
    referenced_symbol: str
    snippet: str
    drift_reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class ChangedFileDelta(BaseModel):
    """Deterministic diff metadata for a single changed file."""

    file_path: str
    old_path: str | None = None
    status: Literal["added", "modified", "deleted", "renamed", "binary", "skipped_large_or_lockfile"]
    insertions: int = 0
    deletions: int = 0
    is_test_file: bool = False
    is_doc_file: bool = False
    hunk_headers: list[str] = Field(default_factory=list)
    bounded_diff: str = ""
    symbol_changes: list[SymbolSignatureChange] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class LogicalChangeStory(BaseModel):
    """Evidence-backed grouping of related code changes."""

    story_id: str
    title: str
    category: ChangeCategory
    confidence: ConfidenceLevel = "high"
    uncertainty_notes: str = ""
    observed_facts: list[str] = Field(
        default_factory=list,
        description="Facts directly observed from Git diffs and ASTs.",
    )
    model_interpretation: str = Field(
        default="",
        description="Technical explanation of why these changes matter and how they relate.",
    )
    potential_risks_requiring_verification: list[str] = Field(
        default_factory=list,
        description="Potential side effects or areas requiring verification.",
    )
    affected_files: list[str] = Field(default_factory=list)
    commit_hashes: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)


class PotentialBreakingChangeFinding(BaseModel):
    """A potential breaking change surfaced for human review (never presented as a guaranteed diagnosis)."""

    finding_id: str
    title: str
    severity: Literal["high", "medium", "low"] = "medium"
    confidence: ConfidenceLevel = "high"
    uncertainty_notes: str = (
        "Static AST and diff analysis verifies structural contract changes; "
        "runtime behavior and external consumer impact require human review."
    )
    affected_symbol: str | None = None
    file_path: str
    change_kind: str
    old_signature: str | None = None
    new_signature: str | None = None
    is_public_api_export: bool = False
    public_api_exposure_reason: str = ""
    observed_facts: list[str] = Field(default_factory=list)
    model_interpretation: str = ""
    potential_risks_requiring_verification: list[str] = Field(default_factory=list)
    affected_callers: list[CallerImpactItem] = Field(default_factory=list)
    unresolved_dynamic_calls: list[UnresolvedDynamicCallItem] = Field(default_factory=list)
    doc_drift: list[DocDriftItem] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    requires_human_review: bool = True


class RepositoryStatusReport(BaseModel):
    """Output contract for MCP Tool 1: inspect_repository."""

    status: Literal["ok", "error"]
    repo_path: str
    is_valid_git_repo: bool
    is_empty_repo: bool = False
    is_shallow_repo: bool = False
    current_branch: str | None = None
    head_commit: CommitSummaryItem | None = None
    branches: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    working_tree_clean: bool = True
    staged_files: list[str] = Field(default_factory=list)
    unstaged_files: list[str] = Field(default_factory=list)
    untracked_files: list[str] = Field(default_factory=list)
    recent_commits: list[CommitSummaryItem] = Field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None


class GitHistoryAnalysisReport(BaseModel):
    """Output contract for MCP Tool 2: analyze_git_history."""

    status: Literal["ok", "error"]
    repo_path: str
    base_ref: str
    target_ref: str
    resolved_base_sha: str = ""
    resolved_target_sha: str = ""
    llm_backend_status: str = "fallback_deterministic"
    total_commits: int = 0
    total_changed_files: int = 0
    total_insertions: int = 0
    total_deletions: int = 0
    commits: list[CommitSummaryItem] = Field(default_factory=list)
    changed_files: list[ChangedFileDelta] = Field(default_factory=list)
    stories: list[LogicalChangeStory] = Field(default_factory=list)
    symbol_changes: list[SymbolSignatureChange] = Field(default_factory=list)
    untested_modified_symbols: list[str] = Field(default_factory=list)
    unresolved_dynamic_calls: list[UnresolvedDynamicCallItem] = Field(default_factory=list)
    analysis_coverage: AnalysisCoverageReport = Field(default_factory=AnalysisCoverageReport)
    doc_drift: list[DocDriftItem] = Field(default_factory=list)
    evidence_registry: dict[str, EvidenceRecord] = Field(default_factory=dict)
    stripped_ungrounded_claims_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None


class BreakingChangeReport(BaseModel):
    """Output contract for MCP Tool 4: detect_potential_breaking_changes."""

    status: Literal["ok", "error"]
    repo_path: str
    base_ref: str
    target_ref: str
    resolved_base_sha: str = ""
    resolved_target_sha: str = ""
    llm_backend_status: str = "fallback_deterministic"
    epistemic_notice: str = (
        "All breaking-change items below are potential breaking changes requiring human review, "
        "not guaranteed diagnoses. Observed AST/diff facts are separated from model interpretations."
    )
    total_potential_breaking_changes: int = 0
    potential_breaking_changes: list[PotentialBreakingChangeFinding] = Field(default_factory=list)
    untested_modified_symbols: list[str] = Field(default_factory=list)
    unresolved_dynamic_calls: list[UnresolvedDynamicCallItem] = Field(default_factory=list)
    analysis_coverage: AnalysisCoverageReport = Field(default_factory=AnalysisCoverageReport)
    doc_drift: list[DocDriftItem] = Field(default_factory=list)
    evidence_registry: dict[str, EvidenceRecord] = Field(default_factory=dict)
    stripped_ungrounded_claims_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None


class ReleaseNotesSection(BaseModel):
    """A single section of a structured release-note draft."""

    heading: str
    items: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class ReleaseNotesReport(BaseModel):
    """Output contract for MCP Tool 3: generate_release_notes."""

    status: Literal["ok", "error"]
    repo_path: str
    base_ref: str
    target_ref: str
    release_version: str = "Unreleased"
    audience: str = "developers"
    llm_backend_status: str = "fallback_deterministic"
    release_summary: str = ""
    sections: list[ReleaseNotesSection] = Field(default_factory=list)
    potential_breaking_changes: list[PotentialBreakingChangeFinding] = Field(default_factory=list)
    unresolved_dynamic_calls: list[UnresolvedDynamicCallItem] = Field(default_factory=list)
    analysis_coverage: AnalysisCoverageReport = Field(default_factory=AnalysisCoverageReport)
    markdown: str = ""
    saved_to_file: str | None = None
    evidence_registry: dict[str, EvidenceRecord] = Field(default_factory=dict)
    stripped_ungrounded_claims_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
