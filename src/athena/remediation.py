"""Deterministic Remediation & Conflict-Free Auto-Fix Engine (`athena fix`).

Translates verified AST/structural breaking findings and doc drift into concrete,
auditable patches tagged with explicit applicability (``safe`` vs
``review_required``), unified diffs, and non-overlapping atomic writes.
"""

from __future__ import annotations

import ast
import difflib
import re
from collections.abc import Iterable
from difflib import SequenceMatcher
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from athena.ast_analyzer import (
    _PyParamInfo,
    _PySymbolInfo,
    _parse_multilang_symbols_rich,
    _parse_py_ast_quietly,
    _parse_python_symbols,
    _unparse_safe,
    detect_python_doc_drift,
    run_structural_code_analysis,
)
from athena.git_inspector import (
    RawRangeExtraction,
    decode_bytes_safely,
    extract_revision_range_data,
    is_non_api_tooling_file,
    read_blob_at_revision,
)
from athena.models import (
    CallerImpactItem,
    PotentialBreakingChangeFinding,
    SymbolSignatureChange,
)
from athena.security import (
    AthenaValidationError,
    is_safe_repo_file,
    redact_model,
    validate_safe_output_path,
    write_text_safely,
)
from athena.treesitter_parser import (
    ParsedCallSpan,
    ParsedMultiLangSymbol,
    extract_ml_param_names,
    extract_multilang_call_spans,
    get_language_family,
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
    source: str = "deterministic"
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
    if len(removed) >= 1 and len(added) == 1:
        target = added[0].lower()
        scored = sorted(
            ((SequenceMatcher(None, r.lower(), target).ratio(), r) for r in removed),
            reverse=True,
        )
        if scored and scored[0][0] >= 0.55 and (len(scored) == 1 or (scored[0][0] - scored[1][0]) >= 0.15):
            return scored[0][1], added[0], old_by
    return None, None, old_by


def _py_is_two_arg_swap(old_sym: _PySymbolInfo | None, new_sym: _PySymbolInfo | None) -> bool:
    if old_sym is None or new_sym is None:
        return False
    old_pos = [p.name for p in old_sym.params if p.kind in ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")]
    new_pos = [p.name for p in new_sym.params if p.kind in ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")]
    return len(old_pos) == 2 and len(new_pos) == 2 and old_pos == list(reversed(new_pos))


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


def _line_byte_offsets(source: str) -> list[int]:
    """Return UTF-8 byte start offset for each 1-indexed line in ``source``."""
    raw = source.encode("utf-8")
    offsets = [0]
    idx = 0
    while True:
        nl = raw.find(b"\n", idx)
        if nl == -1:
            break
        offsets.append(nl + 1)
        idx = nl + 1
    return offsets


def _ast_pos_to_byte(offsets: list[int], lineno: int, col_offset: int, raw_len: int) -> int:
    if lineno < 1 or lineno > len(offsets):
        return raw_len
    return min(raw_len, max(0, offsets[lineno - 1] + col_offset))


def _byte_replacements_to_fix_edits(
    rel_path: str,
    source_text: str,
    replacements: list[tuple[int, int, str]],
) -> list[FixEdit]:
    """Convert non-overlapping UTF-8 byte replacements into 1-indexed line-range FixEdits."""
    if not replacements:
        return []
    raw_bytes = source_text.encode("utf-8")
    sorted_reps = sorted(replacements, key=lambda r: (r[0], r[1]))
    # Validate non-overlapping
    prev_end = -1
    for s_b, e_b, _ in sorted_reps:
        if s_b < 0 or e_b < s_b or e_b > len(raw_bytes) or s_b < prev_end:
            return []
        prev_end = e_b

    lines = source_text.splitlines()
    if not lines:
        return []
    line_byte_spans: list[tuple[int, int]] = []
    pos = 0
    for ln_txt in lines:
        lb = len(ln_txt.encode("utf-8"))
        line_byte_spans.append((pos, pos + lb))
        pos += lb + 1  # '\n'

    def _byte_to_line_idx(b: int) -> int:
        # Binary search 0-indexed line containing byte offset b
        lo, hi = 0, len(line_byte_spans) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            ls, le = line_byte_spans[mid]
            if b < ls:
                hi = mid - 1
            elif b > le + 1:
                lo = mid + 1
            else:
                return mid
        return max(0, min(len(line_byte_spans) - 1, lo))

    # Group replacements touching overlapping line spans
    groups: list[tuple[int, int, list[tuple[int, int, str]]]] = []
    for s_b, e_b, rep_txt in sorted_reps:
        s_li = _byte_to_line_idx(s_b)
        e_li = _byte_to_line_idx(max(s_b, e_b - 1) if e_b > s_b else s_b)
        if groups and s_li <= groups[-1][1]:
            prev_s, prev_e, lst = groups[-1]
            lst.append((s_b, e_b, rep_txt))
            groups[-1] = (prev_s, max(prev_e, e_li), lst)
        else:
            groups.append((s_li, e_li, [(s_b, e_b, rep_txt)]))

    edits: list[FixEdit] = []
    for s_li, e_li, grp in groups:
        span_start_b = line_byte_spans[s_li][0]
        span_end_b = line_byte_spans[e_li][1]
        # Handle pure full-line deletion including newline edge
        e_b = grp[-1][1]
        if e_b > span_end_b and e_li + 1 < len(line_byte_spans):
            e_li += 1
            span_end_b = line_byte_spans[e_li][1]
        orig_slice_lines = lines[s_li : e_li + 1]
        orig_text = "\n".join(orig_slice_lines)
        chunk = raw_bytes[span_start_b:span_end_b]
        buf = bytearray(chunk)
        for sb, eb, rep_txt in sorted(grp, key=lambda r: (r[0], r[1]), reverse=True):
            rel_s = sb - span_start_b
            rel_e = eb - span_start_b
            buf[rel_s:rel_e] = rep_txt.encode("utf-8")
        new_text = bytes(buf).decode("utf-8", errors="replace")
        if new_text != orig_text:
            edits.append(
                FixEdit(
                    file_path=rel_path,
                    start_line=s_li + 1,
                    end_line=e_li + 1,
                    original_text=orig_text,
                    replacement_text=new_text,
                )
            )
    return edits


def _expand_removed_item_span(
    raw_bytes: bytes,
    item_s: int,
    item_e: int,
    container_s: int,
    container_e: int,
) -> tuple[int, int]:
    """Expand an argument/kwarg byte span to cleanly consume separating commas and solo lines."""
    # Check if item sits alone on its own indented line ending with a comma
    line_start = raw_bytes.rfind(b"\n", container_s, item_s)
    line_start = (line_start + 1) if line_start != -1 else container_s
    before_on_line = raw_bytes[line_start:item_s]
    if line_start > container_s and before_on_line.strip(b" \t") == b"":
        i = item_e
        while i < container_e and raw_bytes[i : i + 1] in (b" ", b"\t"):
            i += 1
        if i < container_e and raw_bytes[i : i + 1] == b",":
            j = i + 1
            while j < container_e and raw_bytes[j : j + 1] in (b" ", b"\t"):
                j += 1
            if j < container_e and raw_bytes[j : j + 1] == b"\n":
                # Delete whole line from previous '\n' through before the trailing '\n'
                return line_start - 1, j

    # Check forward comma: `kw=1, ` -> consume through space after comma
    i = item_e
    while i < container_e and raw_bytes[i : i + 1] in (b" ", b"\t", b"\r", b"\n"):
        i += 1
    if i < container_e and raw_bytes[i : i + 1] == b",":
        j = i + 1
        while j < container_e and raw_bytes[j : j + 1] in (b" ", b"\t"):
            j += 1
        return item_s, j

    # Check backward comma: `, kw=1`
    k = item_s - 1
    while k >= container_s and raw_bytes[k : k + 1] in (b" ", b"\t", b"\r", b"\n"):
        k -= 1
    if k >= container_s and raw_bytes[k : k + 1] == b",":
        return k, item_e

    return item_s, item_e


_FALLBACK_ARG_LABEL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:=(?![>=])|:(?![:=]))")
_FALLBACK_DEF_KW = frozenset({"fn", "func", "function", "def", "class", "struct", "interface", "trait", "enum"})


def _extract_multilang_call_spans_fallback(
    source: str,
    target_short_names: set[str],
) -> list[ParsedCallSpan]:
    """Balanced-parenthesis fallback call-span extractor when Tree-sitter is disabled."""
    if not target_short_names or not any(n in source for n in target_short_names):
        return []

    n = len(source)
    char_to_byte = [0] * (n + 1)
    bpos = 0
    for idx, ch in enumerate(source):
        bpos += len(ch.encode("utf-8", errors="replace"))
        char_to_byte[idx + 1] = bpos

    # Build code mask ignoring comments and string literals
    in_code = [True] * n
    i = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1 : i + 2]
        if ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                in_code[i] = False
                i += 1
            continue
        if ch == "#":
            # Skip preprocessor / Ruby / Python comments outside strings
            line_start = source.rfind("\n", 0, i) + 1
            if source[line_start:i].strip() == "" or not source[i:].startswith("#["):
                while i < n and source[i] != "\n":
                    in_code[i] = False
                    i += 1
                continue
        if ch == "/" and nxt == "*":
            in_code[i] = False
            in_code[i + 1] = False
            i += 2
            while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                in_code[i] = False
                i += 1
            for k in range(i, min(n, i + 2)):
                in_code[k] = False
            i += 2
            continue
        if ch in ('"', "'", "`"):
            q = ch
            in_code[i] = False
            i += 1
            esc = False
            while i < n:
                in_code[i] = False
                if esc:
                    esc = False
                elif source[i] == "\\":
                    esc = True
                elif source[i] == q:
                    i += 1
                    break
                i += 1
            continue
        i += 1

    spans: list[ParsedCallSpan] = []
    name_pat = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for m in name_pat.finditer(source):
        callee = m.group(1)
        if callee not in target_short_names:
            continue
        c_start = m.start(1)
        c_end = m.end(1)
        open_paren = m.end() - 1
        if not in_code[c_start] or not in_code[open_paren]:
            continue
        # Skip declaration keywords immediately preceding callee (`func foo(`, `fn foo(`)
        line_start = source.rfind("\n", 0, c_start) + 1
        prefix_toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", source[line_start:c_start])
        if prefix_toks and prefix_toks[-1] in _FALLBACK_DEF_KW:
            continue

        # Match balanced closing ')'
        depth = 1
        j = open_paren + 1
        while j < n and depth > 0:
            if in_code[j]:
                if source[j] == "(":
                    depth += 1
                elif source[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
            j += 1
        if depth != 0:
            continue
        close_paren = j
        # Skip declarations whose closing paren is followed by `{` or `-> ... {` or `where`
        after = source[close_paren + 1 : min(n, close_paren + 80)].lstrip()
        if after.startswith("{"):
            continue

        # Extract immediate receiver if `.`/`->`/`::` precedes callee
        recv: str | None = None
        pre = source[line_start:c_start].rstrip()
        for sep in (".", "->", "::", "\\"):
            if pre.endswith(sep):
                lhs = pre[: -len(sep)].rstrip()
                rm = re.search(r"([A-Za-z_$][A-Za-z0-9_$]*)$", lhs)
                if rm:
                    recv = rm.group(1)
                break

        # Extract top-level argument byte spans inside (open_paren + 1 .. close_paren)
        arg_spans: list[tuple[int, int, str | None]] = []
        a_start = open_paren + 1
        p_d = b_d = br_d = ang_d = 0
        raw_arg_ranges: list[tuple[int, int]] = []
        for k in range(open_paren + 1, close_paren):
            if not in_code[k]:
                continue
            c = source[k]
            if c == "(":
                p_d += 1
            elif c == ")":
                p_d = max(0, p_d - 1)
            elif c == "[":
                b_d += 1
            elif c == "]":
                b_d = max(0, b_d - 1)
            elif c == "{":
                br_d += 1
            elif c == "}":
                br_d = max(0, br_d - 1)
            elif c == "<":
                ang_d += 1
            elif c == ">" and source[k - 1 : k] != "=":
                ang_d = max(0, ang_d - 1)
            elif c == "," and p_d == 0 and b_d == 0 and br_d == 0 and ang_d == 0:
                raw_arg_ranges.append((a_start, k))
                a_start = k + 1
        raw_arg_ranges.append((a_start, close_paren))
        for rs, re_idx in raw_arg_ranges:
            seg = source[rs:re_idx]
            if not seg.strip():
                continue
            ls = rs + (len(seg) - len(seg.lstrip()))
            le = re_idx - (len(seg) - len(seg.rstrip()))
            arg_txt = source[ls:le]
            mlbl = _FALLBACK_ARG_LABEL_RE.match(arg_txt)
            arg_spans.append((char_to_byte[ls], char_to_byte[le], mlbl.group(1) if mlbl else None))

        start_line = source.count("\n", 0, c_start) + 1
        end_line = source.count("\n", 0, close_paren) + 1
        spans.append(
            ParsedCallSpan(
                callee_name=callee,
                receiver=recv,
                start_line=start_line,
                end_line=end_line,
                start_byte=char_to_byte[c_start],
                end_byte=char_to_byte[close_paren + 1],
                callee_start_byte=char_to_byte[c_start],
                callee_end_byte=char_to_byte[c_end],
                arg_spans=arg_spans,
            )
        )

    spans.sort(key=lambda s: (s.start_line, s.callee_start_byte))
    return spans


def _detect_symbol_renames(
    symbol_changes: list[SymbolSignatureChange],
) -> dict[tuple[str, str], str]:
    """Detect probable 1-to-1 symbol renames within the same file/owner scope."""
    grouped_rem: dict[tuple[str, str, str], list[SymbolSignatureChange]] = {}
    grouped_add: dict[tuple[str, str, str], list[SymbolSignatureChange]] = {}

    for sc in symbol_changes:
        q = sc.symbol_name.split("#", 1)[0]
        owner = q.rsplit(".", 1)[0] if "." in q else (q.rsplit("::", 1)[0] if "::" in q else "")
        key = (sc.file_path, owner, sc.symbol_kind)
        if sc.change_kind == "removed":
            grouped_rem.setdefault(key, []).append(sc)
        elif sc.change_kind == "added":
            grouped_add.setdefault(key, []).append(sc)

    renames: dict[tuple[str, str], str] = {}
    for key, rems in grouped_rem.items():
        adds = grouped_add.get(key, [])
        if not adds:
            continue
        if len(rems) == 1 and len(adds) == 1:
            old_q = rems[0].symbol_name.split("#", 1)[0]
            new_q = adds[0].symbol_name.split("#", 1)[0]
            if old_q != new_q:
                renames[(rems[0].file_path, rems[0].symbol_name)] = new_q
                renames[(rems[0].file_path, old_q)] = new_q
            continue

        # Score similarity when multiple removed/added symbols exist in the same scope
        used_adds: set[str] = set()
        candidates: list[tuple[float, SymbolSignatureChange, SymbolSignatureChange]] = []
        for rem in rems:
            r_short = rem.symbol_name.split("#", 1)[0].split(".")[-1].split("::")[-1].lower()
            scored: list[tuple[float, SymbolSignatureChange]] = []
            for add in adds:
                a_short = add.symbol_name.split("#", 1)[0].split(".")[-1].split("::")[-1].lower()
                if a_short == r_short:
                    continue
                ratio = SequenceMatcher(None, r_short, a_short).ratio()
                scored.append((ratio, add))
            scored.sort(key=lambda t: t[0], reverse=True)
            if not scored or scored[0][0] < 0.55:
                continue
            if len(scored) > 1 and (scored[0][0] - scored[1][0]) < 0.15:
                continue
            candidates.append((scored[0][0], rem, scored[0][1]))
        candidates.sort(key=lambda t: t[0], reverse=True)
        for _, rem, add in candidates:
            new_q = add.symbol_name.split("#", 1)[0]
            if new_q in used_adds:
                continue
            used_adds.add(new_q)
            old_q = rem.symbol_name.split("#", 1)[0]
            renames[(rem.file_path, rem.symbol_name)] = new_q
            renames[(rem.file_path, old_q)] = new_q
    return renames


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


def _py_callee_name_byte_span(
    func_node: ast.expr,
    short_name: str,
    offsets: list[int],
    raw_bytes: bytes,
) -> tuple[int, int] | None:
    """Return exact (start_byte, end_byte) of the callee identifier in a Python Call node."""
    s_ln = getattr(func_node, "lineno", None)
    s_col = getattr(func_node, "col_offset", None)
    e_ln = getattr(func_node, "end_lineno", None)
    e_col = getattr(func_node, "end_col_offset", None)
    if None in (s_ln, s_col, e_ln, e_col):
        return None
    sb = _ast_pos_to_byte(offsets, int(s_ln), int(s_col), len(raw_bytes))
    eb = _ast_pos_to_byte(offsets, int(e_ln), int(e_col), len(raw_bytes))
    target_b = short_name.encode("utf-8")
    if isinstance(func_node, ast.Name) and raw_bytes[sb:eb] == target_b:
        return sb, eb
    if isinstance(func_node, ast.Attribute):
        idx = raw_bytes.rfind(b"." + target_b, sb, eb)
        if idx != -1:
            attr_s = idx + 1
            return attr_s, attr_s + len(target_b)
        idx2 = raw_bytes.rfind(target_b, sb, eb)
        if idx2 != -1:
            return idx2, idx2 + len(target_b)
    return None


def _build_py_caller_fixes_for_file(
    next_fix_id_fn,
    finding: PotentialBreakingChangeFinding,
    caller_file: str,
    callers: list[CallerImpactItem],
    old_sym: _PySymbolInfo | None,
    new_sym: _PySymbolInfo | None,
    renamed_to_short: str | None,
    caller_lines: list[str],
) -> list[FixPatch]:
    """Generate deterministic Python caller FixPatches across single- and multi-line calls."""
    if not finding.affected_symbol:
        return []
    if new_sym is None and not renamed_to_short:
        return []

    short_name = finding.affected_symbol.split(".")[-1]
    if short_name in ("__init__", "__call__"):
        short_name = finding.affected_symbol.split(".")[0]

    caller_source = "\n".join(caller_lines)
    try:
        tree = _parse_py_ast_quietly(caller_source)
    except SyntaxError:
        return []

    raw_bytes = caller_source.encode("utf-8")
    offsets = _line_byte_offsets(caller_source)
    raw_len = len(raw_bytes)
    def_stem = Path(finding.file_path).stem

    # Case 0: 1-to-1 Python symbol rename (top-level or method)
    if renamed_to_short and renamed_to_short != short_name:
        safe_reps: list[tuple[int, int, str]] = []
        # Update `from ... import old_name` when module matches definition stem
        if "." not in finding.affected_symbol:
            old_b = short_name.encode("utf-8")
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    mod_tail = (node.module or "").rsplit(".", 1)[-1]
                    if mod_tail and mod_tail != def_stem:
                        continue
                    for alias in node.names:
                        if alias.name == short_name and getattr(alias, "lineno", None) is not None:
                            as_s = _ast_pos_to_byte(offsets, int(alias.lineno), int(alias.col_offset), raw_len)
                            ae_s = _ast_pos_to_byte(
                                offsets,
                                int(getattr(alias, "end_lineno", alias.lineno)),
                                int(getattr(alias, "end_col_offset", alias.col_offset + len(old_b))),
                                raw_len,
                            )
                            pos = raw_bytes.find(old_b, as_s, ae_s)
                            if pos != -1 and raw_bytes[pos : pos + len(old_b)] == old_b:
                                safe_reps.append((pos, pos + len(old_b), renamed_to_short))

        seen_call_spans: set[tuple[int, int]] = set()
        for c in callers:
            if not (1 <= c.line_number <= len(caller_lines)):
                continue
            call_node = _find_call_node_at_line(tree, c.line_number, short_name)
            if call_node is None:
                continue
            span = _py_callee_name_byte_span(call_node.func, short_name, offsets, raw_bytes)
            if span and span not in seen_call_spans:
                seen_call_spans.add(span)
                safe_reps.append((span[0], span[1], renamed_to_short))

        edits = _byte_replacements_to_fix_edits(caller_file, caller_source, safe_reps)
        if edits:
            return [
                FixPatch(
                    fix_id=next_fix_id_fn(),
                    finding_id=finding.finding_id,
                    symbol_name=finding.affected_symbol,
                    file_path=caller_file,
                    category="caller_update",
                    applicability="safe",
                    summary=f"Rename calls `{short_name}` -> `{renamed_to_short}` in `{caller_file}`.",
                    edits=edits,
                    unified_diff=_render_unified_diff(caller_file, caller_lines, edits),
                )
            ]
        return []

    if new_sym is None:
        return []

    renamed_old, renamed_new, old_by = _detect_param_rename_pair(old_sym, new_sym)
    old_pos_names = (
        [p.name for p in old_sym.params if p.kind in ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")]
        if old_sym is not None
        else []
    )
    new_pos_params = [p for p in new_sym.params if p.kind in ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")]
    new_pos_names = [p.name for p in new_pos_params]
    is_two_arg_swap = len(old_pos_names) == 2 and len(new_pos_names) == 2 and old_pos_names == list(reversed(new_pos_names))
    valid_kw = {p.name for p in new_sym.params if p.kind in ("POSITIONAL_OR_KEYWORD", "KEYWORD_ONLY")}
    has_varkw = any(p.kind == "VAR_KEYWORD" for p in new_sym.params)

    safe_reps: list[tuple[int, int, str]] = []
    safe_notes: list[str] = []
    rev_reps: list[tuple[int, int, str]] = []
    rev_notes: list[str] = []

    for caller in callers:
        if not (caller.arity_mismatch_detected or is_two_arg_swap) or not (1 <= caller.line_number <= len(caller_lines)):
            continue
        call_node = _find_call_node_at_line(tree, caller.line_number, short_name)
        if call_node is None:
            continue
        c_end_ln = getattr(call_node, "end_lineno", None)
        c_end_col = getattr(call_node, "end_col_offset", None)
        call_s = _ast_pos_to_byte(offsets, call_node.lineno, call_node.col_offset, raw_len)
        call_e = (
            _ast_pos_to_byte(offsets, int(c_end_ln), int(c_end_col), raw_len)
            if c_end_ln is not None and c_end_col is not None
            else call_s
        )

        handled_kws: set[str] = set()
        # 1. Exact/similar 1-to-1 keyword parameter rename (single- or multi-line) -> safe
        if renamed_old and renamed_new:
            for kw in call_node.keywords:
                if kw.arg == renamed_old and getattr(kw, "lineno", None) is not None:
                    kw_s = _ast_pos_to_byte(offsets, int(kw.lineno), int(kw.col_offset), raw_len)
                    old_kw_b = renamed_old.encode("utf-8")
                    if raw_bytes[kw_s : kw_s + len(old_kw_b)] == old_kw_b:
                        safe_reps.append((kw_s, kw_s + len(old_kw_b), renamed_new))
                        safe_notes.append(f"`{renamed_old}=` -> `{renamed_new}=` at L{caller.line_number}")
                        handled_kws.add(renamed_old)
                        break

        # 2. Safe 2-arg positional swap `(a, b) -> (b, a)`
        if (
            is_two_arg_swap
            and len(call_node.args) == 2
            and not any(isinstance(a, ast.Starred) for a in call_node.args)
            and not call_node.keywords
        ):
            a0, a1 = call_node.args[0], call_node.args[1]
            if None not in (
                getattr(a0, "lineno", None),
                getattr(a0, "end_lineno", None),
                getattr(a1, "lineno", None),
                getattr(a1, "end_lineno", None),
            ):
                a0_s = _ast_pos_to_byte(offsets, int(a0.lineno), int(a0.col_offset), raw_len)
                a0_e = _ast_pos_to_byte(offsets, int(a0.end_lineno), int(a0.end_col_offset), raw_len)
                a1_s = _ast_pos_to_byte(offsets, int(a1.lineno), int(a1.col_offset), raw_len)
                a1_e = _ast_pos_to_byte(offsets, int(a1.end_lineno), int(a1.end_col_offset), raw_len)
                b0 = raw_bytes[a0_s:a0_e].decode("utf-8", errors="replace")
                b1 = raw_bytes[a1_s:a1_e].decode("utf-8", errors="replace")
                safe_reps.append((a0_s, a0_e, b1))
                safe_reps.append((a1_s, a1_e, b0))
                safe_notes.append(f"swap args `{old_pos_names[0]}, {old_pos_names[1]}` at L{caller.line_number}")
                continue

        # 3. Removed keyword argument passed by caller -> strip kwarg cleanly across single/multi-line
        if not has_varkw:
            removed_kws = [
                kw
                for kw in call_node.keywords
                if kw.arg is not None and kw.arg not in valid_kw and kw.arg not in handled_kws
            ]
            if len(removed_kws) == 1 and len(call_node.keywords) >= 1:
                kw_obj = removed_kws[0]
                assert kw_obj.arg is not None
                if getattr(kw_obj, "lineno", None) is not None and getattr(kw_obj, "end_lineno", None) is not None:
                    kw_s = _ast_pos_to_byte(offsets, int(kw_obj.lineno), int(kw_obj.col_offset), raw_len)
                    kw_e = _ast_pos_to_byte(offsets, int(kw_obj.end_lineno), int(kw_obj.end_col_offset), raw_len)
                    open_p = raw_bytes.find(b"(", call_s, call_e)
                    rem_s, rem_e = _expand_removed_item_span(
                        raw_bytes,
                        kw_s,
                        kw_e,
                        (open_p + 1) if open_p != -1 else call_s,
                        max(call_s, call_e - 1),
                    )
                    was_optional = bool(old_by.get(kw_obj.arg) and old_by[kw_obj.arg].has_default)
                    target_list = safe_reps if was_optional else rev_reps
                    note_list = safe_notes if was_optional else rev_notes
                    target_list.append((rem_s, rem_e, ""))
                    note_list.append(f"drop `{kw_obj.arg}=` at L{caller.line_number}")
                    continue
            if handled_kws:
                continue

        # 4. Missing required parameter -> placeholder kwarg (review_required)
        pos_passed = len(call_node.args)
        kw_passed = {kw.arg for kw in call_node.keywords if kw.arg is not None}
        missing_req: list[str] = []
        for idx, p in enumerate(new_pos_params):
            if not p.has_default and idx >= pos_passed and not (p.kind == "POSITIONAL_OR_KEYWORD" and p.name in kw_passed):
                missing_req.append(p.name)
        for p in new_sym.params:
            if p.kind == "KEYWORD_ONLY" and not p.has_default and p.name not in kw_passed:
                missing_req.append(p.name)

        if missing_req and call_e > call_s and raw_bytes[call_e - 1 : call_e] == b")":
            has_existing = bool(call_node.args or call_node.keywords)
            placeholders = ", ".join(f"{m}=TODO_VALUE" for m in missing_req)
            ins = (", " + placeholders) if has_existing else placeholders
            rev_reps.append((call_e - 1, call_e - 1, ins))
            rev_notes.append(f"add required {missing_req} at L{caller.line_number}")

    out: list[FixPatch] = []
    if safe_reps:
        s_edits = _byte_replacements_to_fix_edits(caller_file, caller_source, safe_reps)
        if s_edits:
            out.append(
                FixPatch(
                    fix_id=next_fix_id_fn(),
                    finding_id=finding.finding_id,
                    symbol_name=finding.affected_symbol,
                    file_path=caller_file,
                    category="caller_update",
                    applicability="safe",
                    summary=f"Update call site(s) in `{caller_file}`: " + "; ".join(safe_notes[:4]),
                    edits=s_edits,
                    unified_diff=_render_unified_diff(caller_file, caller_lines, s_edits),
                )
            )
    if rev_reps:
        r_edits = _byte_replacements_to_fix_edits(caller_file, caller_source, rev_reps)
        if r_edits:
            out.append(
                FixPatch(
                    fix_id=next_fix_id_fn(),
                    finding_id=finding.finding_id,
                    symbol_name=finding.affected_symbol,
                    file_path=caller_file,
                    category="caller_update",
                    applicability="review_required",
                    summary=f"Update call site(s) needing values in `{caller_file}`: " + "; ".join(rev_notes[:4]),
                    edits=r_edits,
                    unified_diff=_render_unified_diff(caller_file, caller_lines, r_edits),
                )
            )
    return out


def _build_multilang_caller_fixes(
    next_fix_id_fn,
    finding: PotentialBreakingChangeFinding,
    caller_file: str,
    callers: list[CallerImpactItem],
    old_sym: ParsedMultiLangSymbol | None,
    new_sym: ParsedMultiLangSymbol | None,
    renamed_to_short: str | None,
    caller_lines: list[str],
) -> list[FixPatch]:
    """Generate deterministic multi-language caller patches using Tree-sitter or fallback call spans."""
    if not finding.affected_symbol:
        return []
    old_short = finding.affected_symbol.split("#", 1)[0].split(".")[-1].split("::")[-1]
    if not old_short:
        return []

    caller_source = "\n".join(caller_lines)
    spans = extract_multilang_call_spans(caller_source, caller_file, {old_short})
    if spans is None:
        spans = _extract_multilang_call_spans_fallback(caller_source, {old_short})
    if not spans:
        return []

    raw_bytes = caller_source.encode("utf-8")
    target_lines = {c.line_number for c in callers}
    span_by_line: dict[int, ParsedCallSpan] = {}
    for sp in spans:
        if sp.start_line in target_lines and sp.start_line not in span_by_line:
            span_by_line[sp.start_line] = sp

    safe_reps: list[tuple[int, int, str]] = []
    notes: list[str] = []
    family = finding.language_family or get_language_family(caller_file)

    # 1. 1-to-1 symbol rename (safe)
    if renamed_to_short and renamed_to_short != old_short:
        for ln, sp in sorted(span_by_line.items()):
            if raw_bytes[sp.callee_start_byte : sp.callee_end_byte].decode("utf-8", errors="ignore") == old_short:
                safe_reps.append((sp.callee_start_byte, sp.callee_end_byte, renamed_to_short))
                notes.append(f"`{old_short}` -> `{renamed_to_short}` at L{ln}")

    elif old_sym is not None and new_sym is not None:
        old_pnames = extract_ml_param_names(old_sym.params, family)
        new_pnames = extract_ml_param_names(new_sym.params, family)
        removed_p = [n for n in old_pnames if n and n not in new_pnames]
        added_p = [n for n in new_pnames if n and n not in old_pnames]
        can_rename_label = len(removed_p) == 1 and len(added_p) == 1
        can_drop_trailing = (
            len(old_sym.params) == len(new_sym.params) + 1
            and old_sym.required_param_count <= len(new_sym.params)
            and len(new_sym.params) >= 0
        )

        for caller in callers:
            sp = span_by_line.get(caller.line_number)
            if sp is None:
                continue
            # 2. Named-argument label rename (`timeout: 5` / `timeout = 5`)
            if can_rename_label:
                r_old, r_new = removed_p[0], added_p[0]
                replaced_lbl = False
                for a_s, a_e, lbl in sp.arg_spans:
                    if lbl == r_old and raw_bytes[a_s : a_s + len(r_old.encode("utf-8"))].decode("utf-8", errors="ignore") == r_old:
                        safe_reps.append((a_s, a_s + len(r_old.encode("utf-8")), r_new))
                        notes.append(f"named arg `{r_old}` -> `{r_new}` at L{caller.line_number}")
                        replaced_lbl = True
                        break
                if replaced_lbl:
                    continue

            # 3. Dropped trailing optional parameter
            if caller.arity_mismatch_detected and can_drop_trailing and len(sp.arg_spans) == len(old_sym.params) and sp.arg_spans:
                last_s, last_e, _ = sp.arg_spans[-1]
                rem_s, rem_e = _expand_removed_item_span(raw_bytes, last_s, last_e, sp.start_byte, sp.end_byte - 1)
                safe_reps.append((rem_s, rem_e, ""))
                notes.append(f"drop trailing removed arg at L{caller.line_number}")

    if not safe_reps:
        return []
    edits = _byte_replacements_to_fix_edits(caller_file, caller_source, safe_reps)
    if not edits:
        return []
    return [
        FixPatch(
            fix_id=next_fix_id_fn(),
            finding_id=finding.finding_id,
            symbol_name=finding.affected_symbol,
            file_path=caller_file,
            category="caller_update",
            applicability="safe",
            summary=f"Update {family or 'multi-language'} call site(s) in `{caller_file}`: " + "; ".join(notes[:4]),
            edits=edits,
            unified_diff=_render_unified_diff(caller_file, caller_lines, edits),
        )
    ]


def _build_forwarding_shim_code(
    finding: PotentialBreakingChangeFinding,
    old_py_sym: _PySymbolInfo | None,
    old_ml_sym: ParsedMultiLangSymbol | None,
    renamed_to_short: str | None,
) -> tuple[str, str] | None:
    """Return (shim_source_block, applicability) for removed top-level symbols."""
    sym = (finding.affected_symbol or "").split("#", 1)[0]
    if not sym or "." in sym or "::" in sym:
        return None
    fpath = finding.file_path
    family = finding.language_family or get_language_family(fpath)

    if fpath.endswith(".py") and old_py_sym is not None:
        is_async = old_py_sym.symbol_kind == "async_function"
        def_kw = "async def" if is_async else "def"
        await_kw = "await " if is_async else ""
        if renamed_to_short:
            shim = (
                f"{def_kw} {sym}(*args, **kwargs):\n"
                f"    import warnings\n"
                f'    warnings.warn("{sym} is deprecated; use {renamed_to_short} instead.", DeprecationWarning, stacklevel=2)\n'
                f"    return {await_kw}{renamed_to_short}(*args, **kwargs)"
            )
            return shim, "safe"
        raw_sig = old_py_sym.signature_str.strip()
        # Strip decorators to emit a clean top-level stub
        sig_line = next((ln for ln in raw_sig.splitlines() if ln.lstrip().startswith(("def ", "async def "))), raw_sig)
        shim = (
            f"{sig_line}:\n"
            f"    import warnings\n"
            f'    warnings.warn("{sym} is deprecated and scheduled for removal.", DeprecationWarning, stacklevel=2)\n'
            f"    raise NotImplementedError('Provide forwarding target for deprecated `{sym}`')"
        )
        return shim, "review_required"

    if old_ml_sym is not None and renamed_to_short and old_ml_sym.symbol_kind in ("function", "async_function"):
        param_names = [n for n in extract_ml_param_names(old_ml_sym.params, family) if n]
        args_fwd = ", ".join(param_names) if len(param_names) == len(old_ml_sym.params) else ""
        raw_params = ", ".join(old_ml_sym.params)
        if family == "ts_js" and len(param_names) == len(old_ml_sym.params):
            ret_part = f": {old_ml_sym.return_type}" if old_ml_sym.return_type else ""
            async_kw = "async " if "async" in old_ml_sym.modifiers else ""
            await_kw = "await " if async_kw else ""
            shim = (
                f"/** @deprecated Use `{renamed_to_short}` instead. */\n"
                f"export {async_kw}function {sym}({raw_params}){ret_part} {{\n"
                f"  return {await_kw}{renamed_to_short}({args_fwd});\n"
                f"}}"
            )
            return shim, "review_required"
        if family == "go" and len(param_names) == len(old_ml_sym.params):
            ret_str = f" {old_ml_sym.return_type}" if old_ml_sym.return_type else ""
            ret_stmt = f"return {renamed_to_short}({args_fwd})" if old_ml_sym.return_type else f"{renamed_to_short}({args_fwd})"
            shim = (
                f"// Deprecated: use {renamed_to_short} instead.\n"
                f"func {sym}({raw_params}){ret_str} {{\n"
                f"\t{ret_stmt}\n"
                f"}}"
            )
            return shim, "review_required"
        if family == "rust" and len(param_names) == len(old_ml_sym.params):
            ret_str = f" -> {old_ml_sym.return_type}" if old_ml_sym.return_type else ""
            shim = (
                f'#[deprecated(note = "use {renamed_to_short} instead")]\n'
                f"pub fn {sym}({raw_params}){ret_str} {{\n"
                f"    {renamed_to_short}({args_fwd})\n"
                f"}}"
            )
            return shim, "review_required"
    return None


def _build_compat_or_migration_guide(
    fix_id: str,
    finding: PotentialBreakingChangeFinding,
    old_py_sym: _PySymbolInfo | None,
    old_ml_sym: ParsedMultiLangSymbol | None = None,
    renamed_to_short: str | None = None,
    target_lines: list[str] | None = None,
) -> FixPatch | None:
    sym = finding.affected_symbol or Path(finding.file_path).name
    if is_non_api_tooling_file(finding.file_path):
        if not finding.affected_callers:
            return None
        caller_locs = ", ".join(f"{c.caller_file}:{c.line_number}" for c in finding.affected_callers[:5])
        return FixPatch(
            fix_id=fix_id,
            finding_id=finding.finding_id,
            symbol_name=sym,
            file_path=finding.file_path,
            category="migration_guide",
            applicability="review_required",
            summary=f"Update internal tooling callers of `{sym}` ({finding.change_kind}) at {caller_locs}.",
            edits=[],
            unified_diff="",
        )

    if finding.change_kind == "removed" and "." not in sym and "::" not in sym:
        shim_res = _build_forwarding_shim_code(finding, old_py_sym, old_ml_sym, renamed_to_short)
        if shim_res is not None:
            shim_code, app_tier = shim_res
            edits: list[FixEdit] = []
            udiff = ""
            if target_lines is not None and len(target_lines) >= 1:
                already_def = any(
                    re.match(rf"^(?:async\s+def|def|export\s+(?:async\s+)?function|function|func|pub\s+fn)\s+{re.escape(sym)}\b", ln.strip())
                    for ln in target_lines
                )
                if not already_def:
                    last_ln_idx = len(target_lines)
                    last_ln = target_lines[-1]
                    repl_txt = f"{last_ln}\n\n{shim_code}" if last_ln.strip() else f"{last_ln}\n{shim_code}"
                    edits = [
                        FixEdit(
                            file_path=finding.file_path,
                            start_line=last_ln_idx,
                            end_line=last_ln_idx,
                            original_text=last_ln,
                            replacement_text=repl_txt,
                        )
                    ]
                    udiff = _render_unified_diff(finding.file_path, target_lines, edits)
            action_verb = f"Restore forwarding compatibility shim `{sym}` -> `{renamed_to_short}`" if renamed_to_short else f"Restore deprecation stub for removed public symbol `{sym}`"
            return FixPatch(
                fix_id=fix_id,
                finding_id=finding.finding_id,
                symbol_name=sym,
                file_path=finding.file_path,
                category="compat_shim",
                applicability=app_tier,  # type: ignore[arg-type]
                summary=f"{action_verb} in `{finding.file_path}`.",
                edits=edits,
                unified_diff=udiff,
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


def capture_file_snapshots(repo_root: Path, rel_paths: Iterable[str]) -> dict[str, tuple[bool, str | None]]:
    """Capture original working-tree file contents before applying mutations."""
    snapshots: dict[str, tuple[bool, str | None]] = {}
    for rel in sorted(set(rel_paths)):
        try:
            target = validate_safe_output_path(repo_root, rel, overwrite=True)
        except AthenaValidationError:
            continue
        if target.is_file() and is_safe_repo_file(repo_root, target):
            snapshots[rel] = (True, decode_bytes_safely(target.read_bytes()))
        else:
            snapshots[rel] = (False, None)
    return snapshots


def restore_file_snapshots(repo_root: Path, snapshots: dict[str, tuple[bool, str | None]]) -> int:
    """Restore previously snapshotted working-tree contents atomically."""
    restored = 0
    for rel, (existed, text) in snapshots.items():
        try:
            target = validate_safe_output_path(repo_root, rel, overwrite=True)
        except AthenaValidationError:
            continue
        if existed and text is not None:
            write_text_safely(target, text, overwrite=True)
            restored += 1
        elif not existed and target.is_file() and is_safe_repo_file(repo_root, target):
            target.unlink(missing_ok=True)
            restored += 1
    return restored


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

        disk_text = decode_bytes_safely(safe_target.read_bytes())
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


def _ml_has_param_label_rename(
    old_sym: ParsedMultiLangSymbol | None,
    new_sym: ParsedMultiLangSymbol | None,
    family: str,
) -> bool:
    if old_sym is None or new_sym is None or family not in ("swift", "csharp", "kotlin", "php"):
        return False
    old_pnames = extract_ml_param_names(old_sym.params, family)
    new_pnames = extract_ml_param_names(new_sym.params, family)
    removed_p = [n for n in old_pnames if n and n not in new_pnames]
    added_p = [n for n in new_pnames if n and n not in old_pnames]
    return len(removed_p) == 1 and len(added_p) == 1


def _match_docstring_param_line(line_txt: str, param_name: str, *, active_section: str | None = None) -> str | None:
    """Return docstring style ('sphinx' | 'google' | 'numpy') when ``line_txt`` documents ``param_name``."""
    if f":param {param_name}:" in line_txt:
        return "sphinx"
    if active_section == "google" and re.match(
        rf"^[ \t]{{2,}}\*{{0,2}}{re.escape(param_name)}\s*(?:\([^)\n]*\))?\s*:", line_txt
    ):
        return "google"
    if active_section == "numpy" and re.match(
        rf"^[ \t]*\*{{0,2}}{re.escape(param_name)}\s*(?::\s*.*)?$", line_txt
    ):
        return "numpy"
    return None


def _rename_docstring_param_line(line_txt: str, old_name: str, new_name: str, style: str) -> str:
    if style == "sphinx":
        return line_txt.replace(f":param {old_name}:", f":param {new_name}:", 1)
    return re.sub(
        rf"^([ \t]*\*{{0,2}}){re.escape(old_name)}\b",
        rf"\1{new_name}",
        line_txt,
        count=1,
    )


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

    rename_map = _detect_symbol_renames(structural.symbol_changes)

    old_py_cache: dict[str, dict[str, _PySymbolInfo]] = {}
    new_py_cache: dict[str, dict[str, _PySymbolInfo]] = {}
    old_ml_cache: dict[str, dict[str, ParsedMultiLangSymbol]] = {}
    new_ml_cache: dict[str, dict[str, ParsedMultiLangSymbol]] = {}
    for fdelta in extraction.changed_files:
        b_src = extraction.base_blobs.get(fdelta.file_path, "")
        t_src = extraction.target_blobs.get(fdelta.file_path, "")
        if fdelta.file_path.endswith(".py"):
            if b_src:
                old_py_cache[fdelta.file_path] = _parse_python_symbols(b_src, fdelta.file_path)
            if t_src:
                new_py_cache[fdelta.file_path] = _parse_python_symbols(t_src, fdelta.file_path)
        elif get_language_family(fdelta.file_path):
            if b_src:
                old_ml_cache[fdelta.file_path] = _parse_multilang_symbols_rich(b_src, fdelta.file_path)
            if t_src:
                new_ml_cache[fdelta.file_path] = _parse_multilang_symbols_rich(t_src, fdelta.file_path)

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
        renamed_qname = rename_map.get((finding.file_path, sym_name)) or rename_map.get(
            (finding.file_path, sym_name.split("#", 1)[0])
        )
        renamed_short = renamed_qname.split(".")[-1].split("::")[-1] if renamed_qname else None

        is_py = finding.file_path.endswith(".py")
        old_py_sym = old_py_cache.get(finding.file_path, {}).get(sym_name) if is_py else None
        new_py_sym = new_py_cache.get(finding.file_path, {}).get(sym_name) if is_py else None
        old_ml_sym = None if is_py else old_ml_cache.get(finding.file_path, {}).get(sym_name)
        new_ml_sym = None if is_py else new_ml_cache.get(finding.file_path, {}).get(sym_name)

        produced_for_finding = False
        t_lines = _get_target_lines(extraction, finding.file_path, line_cache)

        if is_py and t_lines is not None:
            rec_patch = _build_recursion_self_fix(_next_fix_id(), finding, t_lines)
            if rec_patch is not None:
                patches.append(rec_patch)
                produced_for_finding = True
            else:
                fix_idx -= 1

            ng_patch = _build_none_guard_fix(_next_fix_id(), finding, old_py_sym, new_py_sym, t_lines)
            if ng_patch is not None:
                patches.append(ng_patch)
                produced_for_finding = True
            else:
                fix_idx -= 1

        # Group affected callers by caller file so multi-call updates merge cleanly without line overlaps
        ml_family = finding.language_family or get_language_family(finding.file_path)
        include_non_arity_callers = (
            bool(renamed_short)
            or (is_py and _py_is_two_arg_swap(old_py_sym, new_py_sym))
            or _ml_has_param_label_rename(old_ml_sym, new_ml_sym, ml_family)
        )
        callers_by_file: dict[str, list[CallerImpactItem]] = {}
        for caller in finding.affected_callers:
            if caller.arity_mismatch_detected or include_non_arity_callers:
                callers_by_file.setdefault(caller.caller_file, []).append(caller)

        for cfile, clist in callers_by_file.items():
            c_lines = _get_target_lines(extraction, cfile, line_cache)
            if c_lines is None:
                continue
            if cfile.endswith(".py"):
                c_patches = _build_py_caller_fixes_for_file(
                    _next_fix_id,
                    finding,
                    cfile,
                    clist,
                    old_py_sym,
                    new_py_sym,
                    renamed_short,
                    c_lines,
                )
            else:
                c_patches = _build_multilang_caller_fixes(
                    _next_fix_id,
                    finding,
                    cfile,
                    clist,
                    old_ml_sym,
                    new_ml_sym,
                    renamed_short,
                    c_lines,
                )
            if c_patches:
                patches.extend(c_patches)
                produced_for_finding = True

        # Emit forwarding shim or migration guidance when unaddressed or public external API
        if not produced_for_finding or finding.is_public_api_export:
            guide_patch = _build_compat_or_migration_guide(
                _next_fix_id(),
                finding,
                old_py_sym,
                old_ml_sym=old_ml_sym,
                renamed_to_short=renamed_short,
                target_lines=t_lines,
            )
            if guide_patch is not None:
                patches.append(guide_patch)
            else:
                fix_idx -= 1

    # Python docstring param drift fixes (Sphinx, Google, NumPy) on changed Python files
    for fdelta in extraction.changed_files:
        if not fdelta.file_path.endswith(".py") or fdelta.is_test_file:
            continue
        t_src = extraction.target_blobs.get(fdelta.file_path)
        if not t_src:
            continue
        t_lines = _get_target_lines(extraction, fdelta.file_path, line_cache)
        if t_lines is None:
            continue
        used_doc_lines: set[int] = set()
        for d_item in detect_python_doc_drift(t_src, fdelta.file_path):
            stale_p: str | None = None
            m_sp = re.search(r":param\s+([A-Za-z_][A-Za-z0-9_]*):", d_item.snippet)
            if m_sp:
                stale_p = m_sp.group(1)
            else:
                m_gn = re.match(r"^\*{0,2}([A-Za-z_][A-Za-z0-9_]*)\b", d_item.snippet.strip())
                if m_gn:
                    stale_p = m_gn.group(1)
            if not stale_p:
                continue

            old_sym = old_py_cache.get(fdelta.file_path, {}).get(d_item.referenced_symbol)
            new_sym = new_py_cache.get(fdelta.file_path, {}).get(d_item.referenced_symbol)
            r_old, r_new, _ = _detect_param_rename_pair(old_sym, new_sym)
            end_search = min(len(t_lines), d_item.line_number + 60)
            active_section: str | None = None
            for idx in range(max(1, d_item.line_number + 1), end_search + 1):
                line_txt = t_lines[idx - 1]
                if idx > d_item.line_number and re.match(r"^(?:async\s+)?def\s+|^[ \t]*class\s+", line_txt):
                    break
                if re.match(r"^[ \t]*(?:Args|Arguments|Parameters)\s*:\s*$", line_txt):
                    active_section = "google"
                    continue
                if idx < len(t_lines) and re.match(r"^[ \t]*(?:Parameters|Other Parameters)\s*$", line_txt) and re.match(r"^[ \t]*-{3,}\s*$", t_lines[idx]):
                    active_section = "numpy"
                    continue
                if re.match(r"^[ \t]*(?:Returns|Raises|Yields|Note|Notes|Examples|Attributes)\s*:\s*$", line_txt):
                    active_section = None
                    continue
                if idx in used_doc_lines:
                    continue
                style = _match_docstring_param_line(line_txt, stale_p, active_section=active_section)
                if style is None:
                    continue
                used_doc_lines.add(idx)
                if r_old == stale_p and r_new:
                    new_line = _rename_docstring_param_line(line_txt, stale_p, r_new, style)
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
                            summary=f"Rename {style} docstring param `{stale_p}` -> `{r_new}` in `{d_item.referenced_symbol}`.",
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
                            summary=f"Remove stale {style} docstring param `{stale_p}` in `{d_item.referenced_symbol}`.",
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
