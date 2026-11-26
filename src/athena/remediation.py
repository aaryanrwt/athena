"""Deterministic Remediation & Conflict-Free Auto-Fix Engine (`athena fix`).

Translates verified AST/structural breaking findings and doc drift into concrete,
auditable patches tagged with explicit applicability (``safe`` vs
``review_required``), unified diffs, and non-overlapping atomic writes.
"""

from __future__ import annotations

import ast
import difflib
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from athena.ast_analyzer import (
    _PyParamInfo,
    _PySymbolInfo,
    _parse_py_ast_quietly,
    _parse_python_symbols,
    _unparse_safe,
    detect_python_doc_drift,
    run_structural_code_analysis,
)
from athena.git_inspector import (
    RawRangeExtraction,
    extract_revision_range_data,
    read_blob_at_revision,
)
from athena.models import CallerImpactItem, PotentialBreakingChangeFinding
from athena.security import (
    AthenaValidationError,
    is_safe_repo_file,
    redact_model,
    validate_safe_output_path,
    write_text_safely,
)


class FixEdit(BaseModel):
    """Single contiguous line-range replacement within a repository file."""

    file_path: str
    start_line: int = Field(ge=1, description="1-indexed inclusive start line.")
    end_line: int = Field(ge=1, description="1-indexed inclusive end line.")
    original_text: str
    replacement_text: str


class FixPatch(BaseModel):
    """Proposed remediation patch with applicability safety level and unified diff."""

    fix_id: str
    finding_id: str | None = None
    symbol_name: str
    file_path: str
    category: Literal[
        "recursion_fix",
        "none_guard",
        "caller_update",
        "docstring_sync",
        "doc_drift_sync",
        "compat_shim",
        "migration_guide",
    ]
    applicability: Literal["safe", "review_required"]
    summary: str
    edits: list[FixEdit] = Field(default_factory=list)
    unified_diff: str = ""
    applied: bool = False
    skipped_reason: str | None = None


class FixPlanReport(BaseModel):
    """Structured output contract for ``athena fix`` and ``generate_fix_plan``."""

    status: Literal["ok", "error"]
    repo_path: str
    base_ref: str
    target_ref: str
    dry_run: bool = True
    total_patches: int = 0
    safe_patches_count: int = 0
    review_required_count: int = 0
    applied_count: int = 0
    skipped_conflicts_count: int = 0
    patches: list[FixPatch] = Field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None


def _get_target_lines(
    extraction: RawRangeExtraction,
    rel_path: str,
    cache: dict[str, list[str]],
) -> list[str] | None:
    if rel_path in cache:
        return cache[rel_path]
    blob = extraction.target_blobs.get(rel_path)
    if blob is None:
        blob = read_blob_at_revision(extraction.repo_path, extraction.resolved_target_sha, rel_path)
    if blob is None:
        return None
    lines = blob.replace("\r\n", "\n").splitlines()
    cache[rel_path] = lines
    return lines


def _render_unified_diff(rel_path: str, base_lines: list[str], edits: list[FixEdit]) -> str:
    if not edits:
        return ""
    updated = list(base_lines)
    for edit in sorted(edits, key=lambda e: (e.start_line, e.end_line), reverse=True):
        s_idx = max(0, edit.start_line - 1)
        e_idx = min(len(updated), edit.end_line)
        repl_lines = edit.replacement_text.splitlines() if edit.replacement_text != "" else []
        updated[s_idx:e_idx] = repl_lines
    diff = difflib.unified_diff(
        base_lines,
        updated,
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
        lineterm="",
    )
    return "\n".join(diff)


def _find_py_func_node(tree: ast.AST, symbol_qname: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    if "." in symbol_qname:
        cls_name, meth_name = symbol_qname.split(".", 1)
        for node in getattr(tree, "body", []):
            if isinstance(node, ast.ClassDef) and node.name == cls_name:
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == meth_name:
                        return item
    else:
        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol_qname:
                return node
    return None


def _first_body_stmt_line(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int | None:
    stmts = list(func_node.body)
    if (
        stmts
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]
    if not stmts:
        return None
    return getattr(stmts[0], "lineno", None)


def _is_safe_literal_repr(expr_str: str | None) -> bool:
    if not expr_str or expr_str == "None":
        return False
    try:
        val = ast.literal_eval(expr_str)
        return isinstance(val, (int, float, bool, str, bytes, tuple)) or val is None
    except (ValueError, SyntaxError):
        return False


def _detect_param_rename_pair(
    old_sym: _PySymbolInfo | None,
    new_sym: _PySymbolInfo | None,
) -> tuple[str | None, str | None, dict[str, _PyParamInfo]]:
    if old_sym is None or new_sym is None:
        return None, None, {}
    old_by = {p.name: p for p in old_sym.params if p.kind not in ("VAR_POSITIONAL", "VAR_KEYWORD")}
    new_names = [p.name for p in new_sym.params if p.kind not in ("VAR_POSITIONAL", "VAR_KEYWORD")]
    removed = [n for n in old_by if n not in new_names]
    added = [n for n in new_names if n not in old_by]
    if len(removed) == 1 and len(added) == 1:
        return removed[0], added[0], old_by
    return None, None, old_by


def _build_recursion_self_fix(
    fix_id: str,
    finding: PotentialBreakingChangeFinding,
    lines: list[str],
) -> FixPatch | None:
    if not finding.affected_symbol or "." not in finding.affected_symbol:
        return None
    details_blob = " ".join(finding.observed_facts)
    if "without 'self.' prefix" not in details_blob:
        return None
    short_name = finding.affected_symbol.split(".")[-1]
    source = "\n".join(lines)
    try:
        tree = _parse_py_ast_quietly(source)
    except SyntaxError:
        return None
    fn_node = _find_py_func_node(tree, finding.affected_symbol)
    if fn_node is None:
        return None

    edits: list[FixEdit] = []
    seen_lines: set[int] = set()
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == short_name:
            ln = getattr(node.func, "lineno", None)
            col = getattr(node.func, "col_offset", None)
            end_col = getattr(node.func, "end_col_offset", None)
            if ln is None or col is None or end_col is None or ln in seen_lines:
                continue
            if 1 <= ln <= len(lines):
                orig = lines[ln - 1]
                # col_offset is UTF-8 byte offset in CPython AST
                raw_bytes = orig.encode("utf-8")
                if raw_bytes[col:end_col].decode("utf-8", errors="ignore") == short_name:
                    new_line = (raw_bytes[:col] + f"self.{short_name}".encode("utf-8") + raw_bytes[end_col:]).decode("utf-8")
                    if new_line != orig:
                        seen_lines.add(ln)
                        edits.append(
                            FixEdit(
                                file_path=finding.file_path,
                                start_line=ln,
                                end_line=ln,
                                original_text=orig,
                                replacement_text=new_line,
                            )
                        )
    if not edits:
        return None
    return FixPatch(
        fix_id=fix_id,
        finding_id=finding.finding_id,
        symbol_name=finding.affected_symbol,
        file_path=finding.file_path,
        category="recursion_fix",
        applicability="safe",
        summary=f"Qualify bare recursive call `{short_name}(...)` with `self.{short_name}(...)` in `{finding.affected_symbol}`.",
        edits=edits,
        unified_diff=_render_unified_diff(finding.file_path, lines, edits),
    )


def _build_none_guard_fix(
    fix_id: str,
    finding: PotentialBreakingChangeFinding,
    old_sym: _PySymbolInfo | None,
    new_sym: _PySymbolInfo | None,
    lines: list[str],
) -> FixPatch | None:
    if old_sym is None or new_sym is None or not finding.affected_symbol:
        return None
    old_by = {p.name: p for p in old_sym.params}
    targets: list[tuple[str, str, bool]] = []
    for np in new_sym.params:
        op = old_by.get(np.name)
        if (
            op is not None
            and op.has_default
            and op.default_repr not in (None, "None")
            and np.has_default
            and np.default_repr == "None"
            and np.name not in new_sym.none_guarded_params
        ):
            targets.append((np.name, str(op.default_repr), _is_safe_literal_repr(op.default_repr)))
    if not targets:
        return None

    source = "\n".join(lines)
    try:
        tree = _parse_py_ast_quietly(source)
    except SyntaxError:
        return None
    fn_node = _find_py_func_node(tree, finding.affected_symbol)
    if fn_node is None:
        return None
    first_ln = _first_body_stmt_line(fn_node)
    if first_ln is None or not (1 <= first_ln <= len(lines)):
        return None

    orig_line = lines[first_ln - 1]
    indent = orig_line[: len(orig_line) - len(orig_line.lstrip(" \t"))]
    guard_blocks = [
        f"{indent}if {pname} is None:\n{indent}    {pname} = {default_expr}"
        for pname, default_expr, _ in targets
    ]
    replacement = "\n".join(guard_blocks) + "\n" + orig_line
    edit = FixEdit(
        file_path=finding.file_path,
        start_line=first_ln,
        end_line=first_ln,
        original_text=orig_line,
        replacement_text=replacement,
    )
    all_safe = all(is_lit for _, _, is_lit in targets)
    param_desc = ", ".join(f"`{p}` -> `{d}`" for p, d, _ in targets)
    return FixPatch(
        fix_id=fix_id,
        finding_id=finding.finding_id,
        symbol_name=finding.affected_symbol,
        file_path=finding.file_path,
        category="none_guard",
        applicability="safe" if all_safe else "review_required",
        summary=f"Inject explicit `None` fallback guard ({param_desc}) in `{finding.affected_symbol}`.",
        edits=[edit],
        unified_diff=_render_unified_diff(finding.file_path, lines, [edit]),
    )


def _find_call_node_at_line(tree: ast.AST, line_number: int, short_name: str) -> ast.Call | None:
    candidates: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == line_number:
            cname = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else (node.func.attr if isinstance(node.func, ast.Attribute) else None)
            )
            if cname == short_name:
                candidates.append(node)
    return candidates[0] if len(candidates) == 1 else None


def _build_py_caller_fix(
    fix_id: str,
    finding: PotentialBreakingChangeFinding,
    caller: CallerImpactItem,
    old_sym: _PySymbolInfo | None,
    new_sym: _PySymbolInfo | None,
    caller_lines: list[str],
) -> FixPatch | None:
    if not finding.affected_symbol or new_sym is None:
        return None
    if not (1 <= caller.line_number <= len(caller_lines)):
        return None

    short_name = finding.affected_symbol.split(".")[-1]
    if short_name in ("__init__", "__call__"):
        short_name = finding.affected_symbol.split(".")[0]

    try:
        tree = _parse_py_ast_quietly("\n".join(caller_lines))
    except SyntaxError:
        return None

    call_node = _find_call_node_at_line(tree, caller.line_number, short_name)
    if call_node is None or getattr(call_node, "end_lineno", caller.line_number) != caller.line_number:
        return None

    orig_line = caller_lines[caller.line_number - 1]
    renamed_old, renamed_new, old_by = _detect_param_rename_pair(old_sym, new_sym)

    # 1. Exact 1-to-1 keyword parameter rename -> safe rewrite
    if renamed_old and renamed_new:
        for kw in call_node.keywords:
            if kw.arg == renamed_old:
                new_line = re.sub(
                    rf"\b{re.escape(renamed_old)}(\s*=)",
                    rf"{renamed_new}\1",
                    orig_line,
                    count=1,
                )
                if new_line != orig_line:
                    edit = FixEdit(
                        file_path=caller.caller_file,
                        start_line=caller.line_number,
                        end_line=caller.line_number,
                        original_text=orig_line,
                        replacement_text=new_line,
                    )
                    return FixPatch(
                        fix_id=fix_id,
                        finding_id=finding.finding_id,
                        symbol_name=finding.affected_symbol,
                        file_path=caller.caller_file,
                        category="caller_update",
                        applicability="safe",
                        summary=f"Rename keyword argument `{renamed_old}=` -> `{renamed_new}=` at `{caller.caller_file}:{caller.line_number}`.",
                        edits=[edit],
                        unified_diff=_render_unified_diff(caller.caller_file, caller_lines, [edit]),
                    )

    # 2. Removed keyword argument passed by caller -> strip kwarg
    valid_kw = {p.name for p in new_sym.params if p.kind in ("POSITIONAL_OR_KEYWORD", "KEYWORD_ONLY")}
    has_varkw = any(p.kind == "VAR_KEYWORD" for p in new_sym.params)
    if not has_varkw:
        removed_kws = [kw for kw in call_node.keywords if kw.arg is not None and kw.arg not in valid_kw]
        if len(removed_kws) == 1 and len(call_node.keywords) >= 1:
            kw_obj = removed_kws[0]
            assert kw_obj.arg is not None
            kw_val_src = _unparse_safe(kw_obj.value) or "..."
            all_args_cnt = len(call_node.args) + len(call_node.keywords)
            if all_args_cnt == 1:
                pat = rf"\s*\b{re.escape(kw_obj.arg)}\s*=\s*{re.escape(kw_val_src)}\s*"
                new_line = re.sub(pat, "", orig_line, count=1)
            else:
                new_line = re.sub(
                    rf",\s*\b{re.escape(kw_obj.arg)}\s*=\s*[^,)]+",
                    "",
                    orig_line,
                    count=1,
                )
                if new_line == orig_line:
                    new_line = re.sub(
                        rf"\b{re.escape(kw_obj.arg)}\s*=\s*[^,)]+,\s*",
                        "",
                        orig_line,
                        count=1,
                    )
            if new_line != orig_line:
                was_optional = bool(old_by.get(kw_obj.arg) and old_by[kw_obj.arg].has_default)
                edit = FixEdit(
                    file_path=caller.caller_file,
                    start_line=caller.line_number,
                    end_line=caller.line_number,
                    original_text=orig_line,
                    replacement_text=new_line,
                )
                return FixPatch(
                    fix_id=fix_id,
                    finding_id=finding.finding_id,
                    symbol_name=finding.affected_symbol,
                    file_path=caller.caller_file,
                    category="caller_update",
                    applicability="safe" if was_optional else "review_required",
                    summary=f"Remove dropped keyword argument `{kw_obj.arg}=` at `{caller.caller_file}:{caller.line_number}`.",
                    edits=[edit],
                    unified_diff=_render_unified_diff(caller.caller_file, caller_lines, [edit]),
                )

    # 3. Missing required parameter -> add placeholder kwarg (review_required)
    pos_passed = len(call_node.args)
    kw_passed = {kw.arg for kw in call_node.keywords if kw.arg is not None}
    pos_params = [p for p in new_sym.params if p.kind in ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")]
    missing_req: list[str] = []
    for idx, p in enumerate(pos_params):
        if not p.has_default and idx >= pos_passed and not (p.kind == "POSITIONAL_OR_KEYWORD" and p.name in kw_passed):
            missing_req.append(p.name)
    for p in new_sym.params:
        if p.kind == "KEYWORD_ONLY" and not p.has_default and p.name not in kw_passed:
            missing_req.append(p.name)

    if missing_req:
        end_col = getattr(call_node, "end_col_offset", None)
        raw_bytes = orig_line.encode("utf-8")
        if end_col is not None and 0 < end_col <= len(raw_bytes) and raw_bytes[end_col - 1 : end_col] == b")":
            has_existing = bool(call_node.args or call_node.keywords)
            placeholders = ", ".join(f"{m}=TODO_VALUE" for m in missing_req)
            ins = (", " + placeholders) if has_existing else placeholders
            new_line = (raw_bytes[: end_col - 1] + ins.encode("utf-8") + raw_bytes[end_col - 1 :]).decode("utf-8")
            edit = FixEdit(
                file_path=caller.caller_file,
                start_line=caller.line_number,
                end_line=caller.line_number,
                original_text=orig_line,
                replacement_text=new_line,
            )
            return FixPatch(
                fix_id=fix_id,
                finding_id=finding.finding_id,
                symbol_name=finding.affected_symbol,
                file_path=caller.caller_file,
                category="caller_update",
                applicability="review_required",
                summary=f"Pass required parameter(s) {missing_req} to `{finding.affected_symbol}` at `{caller.caller_file}:{caller.line_number}`.",
                edits=[edit],
                unified_diff=_render_unified_diff(caller.caller_file, caller_lines, [edit]),
            )
    return None


def _build_compat_or_migration_guide(
    fix_id: str,
    finding: PotentialBreakingChangeFinding,
    old_sym: _PySymbolInfo | None,
) -> FixPatch:
    sym = finding.affected_symbol or Path(finding.file_path).name
    is_py = finding.file_path.endswith(".py")
    if is_py and finding.change_kind == "removed" and "." not in sym and old_sym is not None:
        raw_sig = old_sym.signature_str.strip()
        shim = (
            f"{raw_sig}:\n"
            f"    import warnings\n"
            f'    warnings.warn("{sym} is deprecated and scheduled for removal.", DeprecationWarning, stacklevel=2)\n'
            f"    raise NotImplementedError('Provide forwarding target for deprecated `{sym}`')\n"
        )
        return FixPatch(
            fix_id=fix_id,
            finding_id=finding.finding_id,
            symbol_name=sym,
            file_path=finding.file_path,
            category="compat_shim",
            applicability="review_required",
            summary=(
                f"Restore a deprecation wrapper for removed public Python symbol `{sym}` before next major release.\n"
                f"Suggested shim:\n{shim}"
            ),
            edits=[],
            unified_diff="",
        )

    caller_locs = ", ".join(f"{c.caller_file}:{c.line_number}" for c in finding.affected_callers[:5])
    guide = (
        f"Update callers of `{sym}` ({finding.change_kind}): "
        f"`{finding.old_signature or 'removed'}` -> `{finding.new_signature or 'removed'}`"
        + (f". Affected locations: {caller_locs}." if caller_locs else ".")
    )
    return FixPatch(
        fix_id=fix_id,
        finding_id=finding.finding_id,
        symbol_name=sym,
        file_path=finding.file_path,
        category="migration_guide",
        applicability="review_required",
        summary=guide,
        edits=[],
        unified_diff="",
    )


def _apply_patches_safely(
    repo_root: Path,
    patches: list[FixPatch],
    *,
    include_review_required: bool,
) -> tuple[int, int]:
    """Apply non-overlapping eligible patches atomically with disk-state verification."""
    eligible = [
        p
        for p in patches
        if p.edits and (p.applicability == "safe" or (include_review_required and p.applicability == "review_required"))
    ]
    by_file: dict[str, list[FixPatch]] = {}
    for patch in eligible:
        by_file.setdefault(patch.file_path, []).append(patch)

    applied_count = 0
    conflicts_count = 0

    for rel_path, file_patches in by_file.items():
        try:
            safe_target = validate_safe_output_path(repo_root, rel_path, overwrite=True)
        except AthenaValidationError as exc:
            for p in file_patches:
                p.skipped_reason = f"Path safety check failed ({exc.code}): {exc.message}"
                conflicts_count += 1
            continue

        if not safe_target.is_file() or not is_safe_repo_file(repo_root, safe_target):
            for p in file_patches:
                p.skipped_reason = f"Target file missing or unsafe on disk: {rel_path}"
                conflicts_count += 1
            continue

        disk_text = safe_target.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        trailing_nl = disk_text.endswith("\n")
        disk_lines = disk_text.splitlines()

        accepted_edits: list[FixEdit] = []
        accepted_patches: list[FixPatch] = []
        occupied_spans: list[tuple[int, int]] = []

        for patch in sorted(file_patches, key=lambda pt: (min(e.start_line for e in pt.edits), pt.fix_id)):
            has_conflict = False
            reason: str | None = None
            patch_spans: list[tuple[int, int]] = []
            for edit in patch.edits:
                if edit.start_line < 1 or edit.end_line > len(disk_lines):
                    has_conflict = True
                    reason = f"Line span {edit.start_line}-{edit.end_line} out of bounds on disk."
                    break
                cur_slice = "\n".join(disk_lines[edit.start_line - 1 : edit.end_line])
                if cur_slice != edit.original_text:
                    has_conflict = True
                    reason = "Disk contents changed since analyzed revision (stale line span)."
                    break
                for occ_s, occ_e in occupied_spans + patch_spans:
                    if not (edit.end_line < occ_s or edit.start_line > occ_e):
                        has_conflict = True
                        reason = f"Overlapping edit range conflict on lines {edit.start_line}-{edit.end_line}."
                        break
                if has_conflict:
                    break
                patch_spans.append((edit.start_line, edit.end_line))

            if has_conflict:
                patch.skipped_reason = reason
                conflicts_count += 1
            else:
                occupied_spans.extend(patch_spans)
                accepted_edits.extend(patch.edits)
                accepted_patches.append(patch)

        if accepted_edits:
            updated_lines = list(disk_lines)
            for edit in sorted(accepted_edits, key=lambda e: (e.start_line, e.end_line), reverse=True):
                repl = edit.replacement_text.splitlines() if edit.replacement_text != "" else []
                updated_lines[edit.start_line - 1 : edit.end_line] = repl
            new_text = "\n".join(updated_lines) + ("\n" if trailing_nl and updated_lines else "")
            write_text_safely(safe_target, new_text, overwrite=True)
            for p in accepted_patches:
                p.applied = True
                applied_count += 1

    return applied_count, conflicts_count


def generate_fix_plan(
    repo_path: str | Path,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    *,
    apply: bool = False,
    include_review_required: bool = False,
    include_low_confidence: bool = False,
) -> FixPlanReport:
    """Plan and optionally apply deterministic patches for breaking changes and doc drift."""
    try:
        extraction = extract_revision_range_data(
            repo_path_input=repo_path,
            base_ref=base_ref,
            target_ref=target_ref,
            max_commits=100,
        )
    except AthenaValidationError as exc:
        return FixPlanReport(
            status="error",
            repo_path=str(repo_path),
            base_ref=str(base_ref),
            target_ref=str(target_ref),
            dry_run=not apply,
            error_code=exc.code,
            error_message=exc.message,
        )

    structural = run_structural_code_analysis(extraction)
    findings = list(structural.deterministic_breaking_findings)
    if not include_low_confidence:
        findings = [f for f in findings if f.confidence != "low"]

    old_py_cache: dict[str, dict[str, _PySymbolInfo]] = {}
    new_py_cache: dict[str, dict[str, _PySymbolInfo]] = {}
    for fdelta in extraction.changed_files:
        if fdelta.file_path.endswith(".py"):
            b_src = extraction.base_blobs.get(fdelta.file_path, "")
            t_src = extraction.target_blobs.get(fdelta.file_path, "")
            if b_src:
                old_py_cache[fdelta.file_path] = _parse_python_symbols(b_src, fdelta.file_path)
            if t_src:
                new_py_cache[fdelta.file_path] = _parse_python_symbols(t_src, fdelta.file_path)

    line_cache: dict[str, list[str]] = {}
    patches: list[FixPatch] = []
    fix_idx = 1

    def _next_fix_id() -> str:
        nonlocal fix_idx
        fid = f"fix_{fix_idx:03d}"
        fix_idx += 1
        return fid

    for finding in findings:
        sym_name = finding.affected_symbol or ""
        old_sym = old_py_cache.get(finding.file_path, {}).get(sym_name)
        new_sym = new_py_cache.get(finding.file_path, {}).get(sym_name)
        produced_for_finding = False

        if finding.file_path.endswith(".py"):
            t_lines = _get_target_lines(extraction, finding.file_path, line_cache)
            if t_lines is not None:
                rec_patch = _build_recursion_self_fix(_next_fix_id(), finding, t_lines)
                if rec_patch is not None:
                    patches.append(rec_patch)
                    produced_for_finding = True
                else:
                    fix_idx -= 1

                ng_patch = _build_none_guard_fix(_next_fix_id(), finding, old_sym, new_sym, t_lines)
                if ng_patch is not None:
                    patches.append(ng_patch)
                    produced_for_finding = True
                else:
                    fix_idx -= 1

            for caller in finding.affected_callers:
                if not caller.arity_mismatch_detected or not caller.caller_file.endswith(".py"):
                    continue
                c_lines = _get_target_lines(extraction, caller.caller_file, line_cache)
                if c_lines is None:
                    continue
                c_patch = _build_py_caller_fix(_next_fix_id(), finding, caller, old_sym, new_sym, c_lines)
                if c_patch is not None:
                    patches.append(c_patch)
                    produced_for_finding = True
                else:
                    fix_idx -= 1

        # Emit deprecation/migration guidance if no concrete automated edit covered external/non-Python risk
        if not produced_for_finding or finding.is_public_api_export:
            patches.append(_build_compat_or_migration_guide(_next_fix_id(), finding, old_sym))

    # Python docstring :param drift fixes on changed Python files
    for fdelta in extraction.changed_files:
        if not fdelta.file_path.endswith(".py") or fdelta.is_test_file:
            continue
        t_src = extraction.target_blobs.get(fdelta.file_path)
        if not t_src:
            continue
        t_lines = _get_target_lines(extraction, fdelta.file_path, line_cache)
        if t_lines is None:
            continue
        for d_item in detect_python_doc_drift(t_src, fdelta.file_path):
            stale_match = re.search(r":param\s+([A-Za-z0-9_]+):", d_item.snippet)
            if not stale_match:
                continue
            stale_p = stale_match.group(1)
            old_sym = old_py_cache.get(fdelta.file_path, {}).get(d_item.referenced_symbol)
            new_sym = new_py_cache.get(fdelta.file_path, {}).get(d_item.referenced_symbol)
            r_old, r_new, _ = _detect_param_rename_pair(old_sym, new_sym)
            # Search inside function span for `:param <stale_p>:` line
            end_search = min(len(t_lines), d_item.line_number + 35)
            for idx in range(max(1, d_item.line_number), end_search + 1):
                line_txt = t_lines[idx - 1]
                if f":param {stale_p}:" in line_txt:
                    if r_old == stale_p and r_new:
                        new_line = line_txt.replace(f":param {stale_p}:", f":param {r_new}:", 1)
                        edit = FixEdit(
                            file_path=fdelta.file_path,
                            start_line=idx,
                            end_line=idx,
                            original_text=line_txt,
                            replacement_text=new_line,
                        )
                        patches.append(
                            FixPatch(
                                fix_id=_next_fix_id(),
                                finding_id=None,
                                symbol_name=d_item.referenced_symbol,
                                file_path=fdelta.file_path,
                                category="docstring_sync",
                                applicability="safe",
                                summary=f"Rename docstring tag `:param {stale_p}:` -> `:param {r_new}:` in `{d_item.referenced_symbol}`.",
                                edits=[edit],
                                unified_diff=_render_unified_diff(fdelta.file_path, t_lines, [edit]),
                            )
                        )
                    else:
                        edit = FixEdit(
                            file_path=fdelta.file_path,
                            start_line=idx,
                            end_line=idx,
                            original_text=line_txt,
                            replacement_text="",
                        )
                        patches.append(
                            FixPatch(
                                fix_id=_next_fix_id(),
                                finding_id=None,
                                symbol_name=d_item.referenced_symbol,
                                file_path=fdelta.file_path,
                                category="docstring_sync",
                                applicability="review_required",
                                summary=f"Remove stale docstring tag `:param {stale_p}:` in `{d_item.referenced_symbol}`.",
                                edits=[edit],
                                unified_diff=_render_unified_diff(fdelta.file_path, t_lines, [edit]),
                            )
                        )
                    break

    applied_cnt = 0
    conflicts_cnt = 0
    if apply:
        applied_cnt, conflicts_cnt = _apply_patches_safely(
            extraction.repo_path,
            patches,
            include_review_required=include_review_required,
        )

    safe_cnt = sum(1 for p in patches if p.applicability == "safe")
    rev_cnt = sum(1 for p in patches if p.applicability == "review_required")
    return redact_model(
        FixPlanReport(
            status="ok",
            repo_path=str(extraction.repo_path),
            base_ref=extraction.base_ref,
            target_ref=extraction.target_ref,
            dry_run=not apply,
            total_patches=len(patches),
            safe_patches_count=safe_cnt,
            review_required_count=rev_cnt,
            applied_count=applied_cnt,
            skipped_conflicts_count=conflicts_cnt,
            patches=patches,
        )
    )
