"""Pipeline Orchestrator: Release Notes, Git History Analysis, and Breaking-Change Reports."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from athena.ast_analyzer import run_structural_code_analysis
from athena.git_inspector import extract_revision_range_data
from athena.models import (
    BreakingChangeReport,
    EvidenceRecord,
    GitHistoryAnalysisReport,
    LogicalChangeStory,
    PotentialBreakingChangeFinding,
    ReleaseNotesReport,
    ReleaseNotesSection,
)
from athena.ollama_engine import (
    DEFAULT_ENABLE_LLM,
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OLLAMA_MODEL,
    analyze_changes_with_ollama,
)
from athena.security import (
    AthenaValidationError,
    redact_model,
    redact_secrets,
    validate_safe_output_path,
    write_text_safely,
)

VALID_AUDIENCES = {"end_users", "developers", "maintainers", "clients"}


def run_git_history_analysis(
    repo_path: str | Path,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    max_commits: int = 100,
    use_llm: bool = DEFAULT_ENABLE_LLM,
    ollama_url: str = DEFAULT_OLLAMA_BASE_URL,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    timeout_seconds: float = 90.0,
) -> GitHistoryAnalysisReport:
    """Execute Git history analysis, multi-language AST diffing, and evidence-backed story synthesis."""
    try:
        extraction = extract_revision_range_data(
            repo_path_input=repo_path,
            base_ref=base_ref,
            target_ref=target_ref,
            max_commits=max(1, min(max_commits, 500)),
        )
    except AthenaValidationError as exc:
        return GitHistoryAnalysisReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            resolved_base_sha="",
            resolved_target_sha="",
            llm_backend_status="error",
            error_code=exc.code,
            error_message=exc.message,
        )

    try:
        structural = run_structural_code_analysis(extraction)
    except AthenaValidationError as exc:
        return GitHistoryAnalysisReport(
            status="error",
            repo_path=str(extraction.repo_path),
            base_ref=extraction.base_ref,
            target_ref=extraction.target_ref,
            resolved_base_sha=extraction.resolved_base_sha,
            resolved_target_sha=extraction.resolved_target_sha,
            llm_backend_status="error",
            error_code=exc.code,
            error_message=exc.message,
        )
    stories, _, llm_status, stripped_count, warnings = analyze_changes_with_ollama(
        extraction=extraction,
        structural=structural,
        use_llm=use_llm,
        base_url=ollama_url,
        model=ollama_model,
        timeout_seconds=timeout_seconds,
    )

    total_ins = sum(f.insertions for f in extraction.changed_files)
    total_del = sum(f.deletions for f in extraction.changed_files)

    return redact_model(GitHistoryAnalysisReport(
        status="ok",
        repo_path=str(extraction.repo_path),
        base_ref=extraction.base_ref,
        target_ref=extraction.target_ref,
        resolved_base_sha=extraction.resolved_base_sha,
        resolved_target_sha=extraction.resolved_target_sha,
        llm_backend_status=llm_status,
        total_commits=len(extraction.commits),
        total_changed_files=len(extraction.changed_files),
        total_insertions=total_ins,
        total_deletions=total_del,
        commits=extraction.commits,
        changed_files=extraction.changed_files,
        stories=stories,
        symbol_changes=structural.symbol_changes,
        untested_modified_symbols=structural.untested_modified_symbols,
        doc_drift=structural.doc_drift_items,
        unresolved_dynamic_calls=structural.unresolved_dynamic_calls,
        analysis_coverage=structural.analysis_coverage,
        evidence_registry=extraction.evidence_registry,
        stripped_ungrounded_claims_count=stripped_count,
        warnings=warnings,
    ))


def run_breaking_change_detection(
    repo_path: str | Path,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    include_low_confidence: bool = False,
    use_llm: bool = DEFAULT_ENABLE_LLM,
    ollama_url: str = DEFAULT_OLLAMA_BASE_URL,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    timeout_seconds: float = 90.0,
    max_commits: int = 100,
) -> BreakingChangeReport:
    """Detect potential breaking changes requiring human review with caller & doc blast radius."""
    try:
        extraction = extract_revision_range_data(
            repo_path_input=repo_path,
            base_ref=base_ref,
            target_ref=target_ref,
            max_commits=max(1, min(max_commits, 500)),
        )
    except AthenaValidationError as exc:
        return BreakingChangeReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            resolved_base_sha="",
            resolved_target_sha="",
            llm_backend_status="error",
            error_code=exc.code,
            error_message=exc.message,
        )

    try:
        structural = run_structural_code_analysis(extraction)
    except AthenaValidationError as exc:
        return BreakingChangeReport(
            status="error",
            repo_path=str(extraction.repo_path),
            base_ref=extraction.base_ref,
            target_ref=extraction.target_ref,
            resolved_base_sha=extraction.resolved_base_sha,
            resolved_target_sha=extraction.resolved_target_sha,
            llm_backend_status="error",
            error_code=exc.code,
            error_message=exc.message,
        )
    _, breaking_findings, llm_status, stripped_count, warnings = analyze_changes_with_ollama(
        extraction=extraction,
        structural=structural,
        use_llm=use_llm,
        base_url=ollama_url,
        model=ollama_model,
        timeout_seconds=timeout_seconds,
    )

    if not include_low_confidence:
        breaking_findings = [f for f in breaking_findings if f.confidence != "low"]

    return redact_model(BreakingChangeReport(
        status="ok",
        repo_path=str(extraction.repo_path),
        base_ref=extraction.base_ref,
        target_ref=extraction.target_ref,
        resolved_base_sha=extraction.resolved_base_sha,
        resolved_target_sha=extraction.resolved_target_sha,
        llm_backend_status=llm_status,
        total_potential_breaking_changes=len(breaking_findings),
        potential_breaking_changes=breaking_findings,
        untested_modified_symbols=structural.untested_modified_symbols,
        doc_drift=structural.doc_drift_items,
        unresolved_dynamic_calls=structural.unresolved_dynamic_calls,
        analysis_coverage=structural.analysis_coverage,
        evidence_registry=extraction.evidence_registry,
        stripped_ungrounded_claims_count=stripped_count,
        warnings=warnings,
    ))


def _format_evidence_citation(evidence_list: list[EvidenceRecord]) -> str:
    """Format compact inline evidence citation with commit short hash, file/line span, and evidence_id."""
    if not evidence_list:
        return ""
    badges: list[str] = []
    for ev in evidence_list[:2]:
        short_c = ev.commit_hash[:8] if ev.commit_hash else "working"
        span_str = ""
        if ev.target_line_span:
            span_str = f":{ev.target_line_span.start_line}-{ev.target_line_span.end_line}"
        elif ev.base_line_span:
            span_str = f":{ev.base_line_span.start_line}-{ev.base_line_span.end_line}"
        badges.append(f"`{short_c}` `{ev.file_path}{span_str}` [{ev.evidence_id}]")
    return " — " + ", ".join(badges)


def _format_story_bullet(
    story: LogicalChangeStory,
    audience: str,
) -> str:
    citation = _format_evidence_citation(story.evidence)
    if audience in ("end_users", "clients"):
        return f"- **{story.title}**: {story.model_interpretation}{citation}"
    # For developers and maintainers, explicitly show observed facts + interpretation + confidence
    fact_summary = story.observed_facts[0] if story.observed_facts else ""
    risk_suffix = ""
    if audience == "maintainers" and story.potential_risks_requiring_verification:
        risk_suffix = f" *(Review: {story.potential_risks_requiring_verification[0]})*"
    return (
        f"- **{story.title}** (`confidence={story.confidence}`): {story.model_interpretation} "
        f"*(Observed: {fact_summary})*{risk_suffix}{citation}"
    )


def _format_breaking_bullet(finding: PotentialBreakingChangeFinding, audience: str) -> str:
    citation = _format_evidence_citation(finding.evidence)
    sig_delta = ""
    if finding.old_signature or finding.new_signature:
        sig_delta = f" (`{finding.old_signature or 'none'}` -> `{finding.new_signature or 'removed'}`)"
    export_badge = " | `Public API Export`" if finding.is_public_api_export else ""
    caller_note = ""
    if finding.affected_callers:
        locs = ", ".join(f"`{c.caller_file}:{c.line_number}`" for c in finding.affected_callers[:3])
        broken_cnt = sum(1 for c in finding.affected_callers if c.arity_mismatch_detected)
        broken_suffix = f", {broken_cnt} arity-broken" if broken_cnt else ""
        caller_note = f" | Affected callers ({len(finding.affected_callers)}{broken_suffix}): {locs}"
    drift_note = ""
    if finding.doc_drift:
        dlocs = ", ".join(f"`{d.doc_file}:{d.line_number}`" for d in finding.doc_drift[:2])
        drift_note = f" | Stale docs: {dlocs}"

    if audience in ("end_users", "clients"):
        return (
            f"- **[Requires Review] {finding.title}**{sig_delta}: "
            f"{finding.model_interpretation}{citation}"
        )
    return (
        f"- **[Requires Human Review | severity={finding.severity} | confidence={finding.confidence}{export_badge}] {finding.title}**"
        f"{sig_delta}: {finding.model_interpretation}{caller_note}{drift_note}{citation}"
    )


def run_release_notes_generation(
    repo_path: str | Path,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    release_version: str = "Unreleased",
    audience: str = "developers",
    output_file: str | None = None,
    overwrite: bool = False,
    use_llm: bool = DEFAULT_ENABLE_LLM,
    ollama_url: str = DEFAULT_OLLAMA_BASE_URL,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    timeout_seconds: float = 90.0,
    max_commits: int = 100,
) -> ReleaseNotesReport:
    """Generate structured, audience-tailored release notes with optional safe Markdown save."""
    audience_clean = (audience or "developers").strip().lower()
    if audience_clean not in VALID_AUDIENCES:
        return ReleaseNotesReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            release_version=release_version,
            audience=audience_clean,  # type: ignore[arg-type]
            llm_backend_status="error",
            release_summary="",
            markdown="",
            error_code="INVALID_AUDIENCE",
            error_message=f"Invalid audience '{audience}'. Must be one of: {sorted(VALID_AUDIENCES)}.",
        )

    try:
        extraction = extract_revision_range_data(
            repo_path_input=repo_path,
            base_ref=base_ref,
            target_ref=target_ref,
            max_commits=max(1, min(max_commits, 500)),
        )
    except AthenaValidationError as exc:
        return ReleaseNotesReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            release_version=release_version,
            audience=audience_clean,  # type: ignore[arg-type]
            llm_backend_status="error",
            release_summary="",
            markdown="",
            error_code=exc.code,
            error_message=exc.message,
        )

    # Pre-validate output_file before running analysis so overwrite errors fail fast and safely
    validated_out_path: Path | None = None
    if output_file is not None and str(output_file).strip():
        try:
            validated_out_path = validate_safe_output_path(
                extraction.repo_path,
                output_file,
                overwrite=overwrite,
            )
        except AthenaValidationError as exc:
            return ReleaseNotesReport(
                status="error",
                repo_path=str(extraction.repo_path),
                base_ref=extraction.base_ref,
                target_ref=extraction.target_ref,
                release_version=release_version,
                audience=audience_clean,  # type: ignore[arg-type]
                llm_backend_status="error",
                release_summary="",
                markdown="",
                error_code=exc.code,
                error_message=exc.message,
            )

    try:
        structural = run_structural_code_analysis(extraction)
    except AthenaValidationError as exc:
        return ReleaseNotesReport(
            status="error",
            repo_path=str(extraction.repo_path),
            base_ref=extraction.base_ref,
            target_ref=extraction.target_ref,
            resolved_base_sha=extraction.resolved_base_sha,
            resolved_target_sha=extraction.resolved_target_sha,
            release_version=release_version,
            audience=audience_clean,  # type: ignore[arg-type]
            llm_backend_status="error",
            release_summary="",
            markdown="",
            error_code=exc.code,
            error_message=exc.message,
        )
    stories, breaking_findings, llm_status, stripped_count, warnings = analyze_changes_with_ollama(
        extraction=extraction,
        structural=structural,
        use_llm=use_llm,
        base_url=ollama_url,
        model=ollama_model,
        timeout_seconds=timeout_seconds,
    )

    # Build audience-tailored Release Summary
    num_commits = len(extraction.commits)
    num_files = len(extraction.changed_files)
    num_brk = len(breaking_findings)
    if num_commits == 0 and num_files == 0:
        summary_text = (
            f"No commits or file modifications detected between `{extraction.base_ref}` "
            f"(`{extraction.resolved_base_sha[:8]}`) and `{extraction.target_ref}`."
        )
    else:
        audience_label = {
            "end_users": "End-User Summary",
            "developers": "Developer Technical Summary",
            "maintainers": "Maintainer Release & Risk Audit Summary",
            "clients": "Client Integration Summary",
        }[audience_clean]
        summary_text = (
            f"**{audience_label}**: Release `{release_version}` (`{extraction.base_ref}` -> `{extraction.target_ref}`) "
            f"spans {num_commits} commit(s) across {num_files} changed file(s), synthesized into {len(stories)} "
            f"evidence-backed change stories and {num_brk} potential breaking change(s) requiring human review."
        )

    sections: list[ReleaseNotesSection] = []

    def _add_section_if_nonempty(title: str, items: list[str], ev_ids: list[str]) -> None:
        if items:
            sections.append(
                ReleaseNotesSection(
                    heading=title,
                    items=items,
                    evidence_ids=list(dict.fromkeys(ev_ids)),
                )
            )

    # 1. Potential Breaking Changes (Requires Review) — placed prominently if non-empty
    if breaking_findings:
        brk_items = [_format_breaking_bullet(bf, audience_clean) for bf in breaking_findings]
        brk_ev = [eid for bf in breaking_findings for eid in bf.evidence_ids]
        _add_section_if_nonempty("Potential Breaking Changes (Requires Review)", brk_items, brk_ev)

    # 2. New Features
    feat_stories = [s for s in stories if s.category == "feature"]
    _add_section_if_nonempty(
        "New Features",
        [_format_story_bullet(s, audience_clean) for s in feat_stories],
        [eid for s in feat_stories for eid in s.evidence_ids],
    )

    # 3. Improvements
    imp_stories = [s for s in stories if s.category == "improvement"]
    _add_section_if_nonempty(
        "Improvements",
        [_format_story_bullet(s, audience_clean) for s in imp_stories],
        [eid for s in imp_stories for eid in s.evidence_ids],
    )

    # 4. Bug Fixes
    fix_stories = [s for s in stories if s.category == "bug_fix"]
    _add_section_if_nonempty(
        "Bug Fixes",
        [_format_story_bullet(s, audience_clean) for s in fix_stories],
        [eid for s in fix_stories for eid in s.evidence_ids],
    )

    # 5. Refactoring & Internal Changes (included for developers/maintainers, or if no other story sections exist)
    ref_stories = [s for s in stories if s.category in ("refactoring", "docs_or_tests")]
    if ref_stories and (audience_clean in ("developers", "maintainers") or not sections):
        _add_section_if_nonempty(
            "Refactoring & Internal Changes",
            [_format_story_bullet(s, audience_clean) for s in ref_stories],
            [eid for s in ref_stories for eid in s.evidence_ids],
        )

    # 6. Upgrade Considerations
    upgrade_items: list[str] = []
    upgrade_ev_ids: list[str] = []
    for bf in breaking_findings:
        for risk in bf.potential_risks_requiring_verification[:2]:
            upgrade_items.append(f"- **`{bf.affected_symbol or bf.file_path}`**: {risk}")
        upgrade_ev_ids.extend(bf.evidence_ids[:1])
    for dd in structural.doc_drift_items:
        upgrade_items.append(
            f"- **Documentation Drift (`{dd.doc_file}:{dd.line_number}`)**: {dd.drift_reason}"
        )
        upgrade_ev_ids.extend(dd.evidence_ids)
    if structural.unresolved_dynamic_calls and (audience_clean in ("developers", "maintainers") or breaking_findings):
        dyn_locs = ", ".join(
            f"`{d.file_path}:{d.line_number}` (`{d.pattern_kind}`)"
            for d in structural.unresolved_dynamic_calls[:4]
        )
        upgrade_items.append(
            f"- **Unresolved Dynamic Dispatch ({len(structural.unresolved_dynamic_calls)} site(s))**: "
            f"Static caller graph cannot resolve reflection/dynamic dispatch at {dyn_locs}."
        )
    if audience_clean == "maintainers" and structural.untested_modified_symbols:
        upgrade_items.append(
            f"- **Test Coverage Gap**: Modified public symbol(s) without detected test references: "
            f"{', '.join(f'`{s}`' for s in structural.untested_modified_symbols[:6])}."
        )
    upgrade_items = list(dict.fromkeys(upgrade_items))
    _add_section_if_nonempty("Upgrade Considerations", upgrade_items, upgrade_ev_ids)

    cov = structural.analysis_coverage
    cov_line = (
        f"- **Static Analysis Coverage**: `{cov.static_parse_coverage_pct}%` "
        f"(`{cov.files_parsed_successfully}/{cov.total_code_files_eligible}` code files parsed, "
        f"blast-radius confidence=`{cov.overall_blast_radius_confidence}`, "
        f"unresolved dynamic calls=`{cov.unresolved_dynamic_calls_count}`)"
    )

    # Render Markdown document (omitting empty sections)
    md_lines = [
        f"# Release Notes — {release_version}",
        "",
        f"- **Revision Range**: `{extraction.base_ref}` (`{extraction.resolved_base_sha[:8]}`) -> `{extraction.target_ref}` (`{extraction.resolved_target_sha[:8] if extraction.resolved_target_sha != 'WORKING_TREE' else 'WORKING_TREE'}`)",
        f"- **Target Audience**: `{audience_clean}`",
        f"- **Analysis Engine**: `{llm_status}`",
        cov_line,
        "",
        "## Release Summary",
        "",
        summary_text,
        "",
    ]

    for sec in sections:
        md_lines.append(f"## {sec.heading}")
        md_lines.append("")
        for item in sec.items:
            md_lines.append(item)
        md_lines.append("")

    markdown_doc = redact_secrets("\n".join(md_lines).strip() + "\n")

    saved_path_str: str | None = None
    if validated_out_path is not None:
        try:
            write_text_safely(validated_out_path, markdown_doc, overwrite=overwrite)
        except AthenaValidationError as exc:
            return ReleaseNotesReport(
                status="error",
                repo_path=str(extraction.repo_path),
                base_ref=extraction.base_ref,
                target_ref=extraction.target_ref,
                release_version=release_version,
                audience=audience_clean,  # type: ignore[arg-type]
                llm_backend_status="error",
                release_summary="",
                markdown="",
                error_code=exc.code,
                error_message=exc.message,
            )
        saved_path_str = str(validated_out_path)

    return redact_model(ReleaseNotesReport(
        status="ok",
        repo_path=str(extraction.repo_path),
        base_ref=extraction.base_ref,
        target_ref=extraction.target_ref,
        release_version=release_version,
        audience=audience_clean,  # type: ignore[arg-type]
        llm_backend_status=llm_status,
        release_summary=summary_text,
        sections=sections,
        potential_breaking_changes=breaking_findings,
        unresolved_dynamic_calls=structural.unresolved_dynamic_calls,
        analysis_coverage=structural.analysis_coverage,
        markdown=markdown_doc,
        saved_to_file=saved_path_str,
        evidence_registry=extraction.evidence_registry,
        stripped_ungrounded_claims_count=stripped_count,
        warnings=warnings,
    ))

