"""Capability B & D: Deterministic AST Signature Differ, Caller Blast-Radius Scanner, Dynamic Call Detector, and Doc-Drift Detector."""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path

from athena.git_inspector import (
    RawRangeExtraction,
    _is_lockfile_or_generated,
    _is_test_file,
    decode_bytes_safely,
    git_grep_matching_files,
    read_blob_at_revision,
    read_blobs_at_revision,
    run_git_command,
)
from athena.models import (
    AnalysisCoverageReport,
    CallerImpactItem,
    ConfidenceLevel,
    DocDriftItem,
    EvidenceRecord,
    LineSpan,
    PotentialBreakingChangeFinding,
    SymbolSignatureChange,
    UnresolvedDynamicCallItem,
)
from athena.security import is_safe_repo_file
from athena.symbol_cache import compute_cache_key, get_active_cache
from athena.treesitter_parser import (
    ParsedCallSite,
    ParsedMultiLangSymbol,
    _parse_params_from_raw,
    _preprocess_cpp_export_macros,
    _store_symbol,
    compute_multilang_visibility,
    extract_multilang_calls_treesitter,
    get_language_family,
    get_treesitter_status,
    is_treesitter_available,
    normalize_modifiers_and_return,
    normalize_type_expr,
    parse_multilang_symbols_treesitter,
    resolve_visibility_from_modifiers,
)

_ENUM_BASE_NAMES = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag", "ReprEnum"}


@dataclass
class _PyParamInfo:
    name: str
    kind: str  # POSITIONAL_ONLY, POSITIONAL_OR_KEYWORD, VAR_POSITIONAL, KEYWORD_ONLY, VAR_KEYWORD
    has_default: bool
    default_repr: str | None
    annotation_repr: str | None


@dataclass
class _PySymbolInfo:
    qualified_name: str
    short_name: str
    symbol_kind: str  # function, async_function, class, method, enum, constant
    start_line: int
    end_line: int
    signature_str: str
    params: list[_PyParamInfo] = field(default_factory=list)
    return_annotation: str | None = None
    decorators: list[str] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)
    raised_exceptions: set[str] = field(default_factory=set)
    none_guarded_params: set[str] = field(default_factory=set)
    enum_members: dict[str, str] = field(default_factory=dict)
    body_ast_dump: str = ""
    is_public_export: bool = True
    export_reason: str = ""
    is_recursive: bool = False
    has_unconditional_recursion: bool = False
    recursive_arity_mismatches: list[str] = field(default_factory=list)
    unqualified_method_self_calls: list[str] = field(default_factory=list)


@dataclass
class StructuralAnalysisResult:
    symbol_changes: list[SymbolSignatureChange] = field(default_factory=list)
    caller_impacts: dict[str, list[CallerImpactItem]] = field(default_factory=dict)
    doc_drift_items: list[DocDriftItem] = field(default_factory=list)
    untested_modified_symbols: list[str] = field(default_factory=list)
    unresolved_dynamic_calls: list[UnresolvedDynamicCallItem] = field(default_factory=list)
    analysis_coverage: AnalysisCoverageReport = field(default_factory=AnalysisCoverageReport)
    deterministic_breaking_findings: list[PotentialBreakingChangeFinding] = field(default_factory=list)


def _parse_py_ast_quietly(source_code: str) -> ast.Module:
    """Parse Python source into an AST while suppressing third-party SyntaxWarning noise."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(source_code)


def _unparse_safe(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node).strip()
    except (Exception, RecursionError):
        return None


def _compute_body_ast_dump(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Compute a normalized AST dump of function body statements (ignoring leading docstring)."""
    stmts = list(func_node.body)
    if (
        stmts
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]
    try:
        return "\n".join(ast.dump(s, include_attributes=False) for s in stmts)
    except (Exception, RecursionError):
        return ""


def _extract_raised_exceptions(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Detect explicitly raised exception class names inside a function body (griffe#498)."""
    raised: set[str] = set()
    try:
        for child in ast.walk(func_node):
            if isinstance(child, ast.Raise) and child.exc is not None:
                if isinstance(child.exc, ast.Call):
                    exc_name = _unparse_safe(child.exc.func)
                    if exc_name:
                        raised.add(exc_name.split(".")[-1])
                elif isinstance(child.exc, ast.Name):
                    raised.add(child.exc.id)
    except RecursionError:
        pass
    return raised


def _extract_none_guarded_params(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Detect `if param is None:` or `param = param or ...` body guards (griffe#469)."""
    guarded: set[str] = set()
    try:
        for child in ast.walk(func_node):
            if isinstance(child, ast.Compare):
                left_str = _unparse_safe(child.left)
                for op, comp in zip(child.ops, child.comparators):
                    comp_str = _unparse_safe(comp)
                    if isinstance(op, (ast.Is, ast.Eq)):
                        if comp_str == "None" and left_str:
                            guarded.add(left_str)
                        elif left_str == "None" and comp_str:
                            guarded.add(comp_str)
            elif isinstance(child, ast.Assign):
                if isinstance(child.value, ast.BoolOp) and isinstance(child.value.op, ast.Or):
                    if child.value.values:
                        first = _unparse_safe(child.value.values[0])
                        if first:
                            guarded.add(first)
    except RecursionError:
        pass
    return guarded


def _extract_py_params(args: ast.arguments, is_method: bool = False) -> list[_PyParamInfo]:
    params: list[_PyParamInfo] = []
    posonly = list(args.posonlyargs)
    regular = list(args.args)
    all_pos = posonly + regular
    num_pos_defaults = len(args.defaults)
    first_default_idx = len(all_pos) - num_pos_defaults

    for idx, arg in enumerate(all_pos):
        if is_method and idx == 0 and arg.arg in ("self", "cls"):
            continue
        has_def = idx >= first_default_idx
        def_node = args.defaults[idx - first_default_idx] if has_def else None
        kind = "POSITIONAL_ONLY" if idx < len(posonly) else "POSITIONAL_OR_KEYWORD"
        params.append(
            _PyParamInfo(
                name=arg.arg,
                kind=kind,
                has_default=has_def,
                default_repr=_unparse_safe(def_node) if has_def else None,
                annotation_repr=_unparse_safe(arg.annotation),
            )
        )

    if args.vararg is not None:
        params.append(
            _PyParamInfo(
                name=args.vararg.arg,
                kind="VAR_POSITIONAL",
                has_default=True,
                default_repr=None,
                annotation_repr=_unparse_safe(args.vararg.annotation),
            )
        )

    for kw_arg, kw_def in zip(args.kwonlyargs, args.kw_defaults):
        has_def = kw_def is not None
        params.append(
            _PyParamInfo(
                name=kw_arg.arg,
                kind="KEYWORD_ONLY",
                has_default=has_def,
                default_repr=_unparse_safe(kw_def) if has_def else None,
                annotation_repr=_unparse_safe(kw_arg.annotation),
            )
        )

    if args.kwarg is not None:
        params.append(
            _PyParamInfo(
                name=args.kwarg.arg,
                kind="VAR_KEYWORD",
                has_default=True,
                default_repr=None,
                annotation_repr=_unparse_safe(args.kwarg.annotation),
            )
        )

    return params


def _format_py_signature(
    name: str,
    params: list[_PyParamInfo],
    return_annotation: str | None,
    decorators: list[str],
    is_async: bool = False,
) -> str:
    parts: list[str] = []
    has_posonly = any(p.kind == "POSITIONAL_ONLY" for p in params)
    posonly_closed = False
    kw_only_started = False
    for idx, p in enumerate(params):
        if has_posonly and not posonly_closed and p.kind != "POSITIONAL_ONLY":
            parts.append("/")
            posonly_closed = True
        if p.kind == "KEYWORD_ONLY" and not kw_only_started:
            prev_was_varpos = idx > 0 and params[idx - 1].kind == "VAR_POSITIONAL"
            if not prev_was_varpos:
                parts.append("*")
            kw_only_started = True
        prefix = "*" if p.kind == "VAR_POSITIONAL" else ("**" if p.kind == "VAR_KEYWORD" else "")
        seg = f"{prefix}{p.name}"
        if p.annotation_repr:
            seg += f": {p.annotation_repr}"
        if p.has_default and p.default_repr is not None:
            seg += f" = {p.default_repr}"
        parts.append(seg)
    if has_posonly and not posonly_closed:
        parts.append("/")
    ret_str = f" -> {return_annotation}" if return_annotation else ""
    kw = "async def" if is_async else "def"
    dec_prefix = "".join(f"@{d} " for d in decorators) if decorators else ""
    return f"{dec_prefix}{kw} {name}({', '.join(parts)}){ret_str}"


def _extract_dunder_all(tree: ast.Module) -> set[str] | None:
    """Extract explicitly declared `__all__` export names if `__all__` is defined in the module."""
    exported: set[str] | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if exported is None:
                        exported = set()
                    if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                exported.add(elt.value)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "__all__" and node.value is not None:
                if exported is None:
                    exported = set()
                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            exported.add(elt.value)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "__all__":
                if exported is None:
                    exported = set()
                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            exported.add(elt.value)
    return exported


def _determine_py_export_exposure(
    top_symbol_name: str,
    file_path: str,
    dunder_all: set[str] | None,
    init_reexports: set[str] | None = None,
) -> tuple[bool, str]:
    """Determine if a Python symbol is part of the public API surface exposed to external consumers."""
    norm_path = file_path.replace("\\", "/")
    parts = [p for p in norm_path.split("/") if p]

    if dunder_all is not None:
        if top_symbol_name in dunder_all:
            return True, f"Explicitly exported in `__all__` of `{norm_path}`"
        return False, f"Omitted from explicit `__all__` in `{norm_path}`"

    if init_reexports and top_symbol_name in init_reexports:
        return True, "Re-exported in package root `__init__.py`"

    if norm_path.endswith("__init__.py"):
        return True, f"Defined in package entrypoint `{norm_path}`"

    is_private_path = any(
        (seg.startswith("_") and seg != "__init__.py")
        or seg
        in (
            "internal",
            "_internal",
            "tests",
            "test",
            "templates",
            "template",
            "scripts",
            "examples",
            "samples",
            "benchmarks",
            ".github",
            "demo",
        )
        for seg in parts
    )
    if is_private_path:
        return False, f"Internal/private or auxiliary module path `{norm_path}`"

    return True, f"Public top-level symbol in module `{norm_path}`"


def _is_enum_class(bases: list[str]) -> bool:
    for b in bases:
        short_b = b.split(".")[-1]
        if short_b in _ENUM_BASE_NAMES:
            return True
    return False


def _extract_py_imports(tree: ast.AST) -> dict[str, str]:
    """Extract imported symbols and modules mapping alias/name to full import source path."""
    imports: dict[str, str] = {}
    try:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    asname = alias.asname or alias.name
                    imports[asname] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    asname = alias.asname or alias.name
                    imports[asname] = f"{mod}.{alias.name}" if mod else alias.name
    except RecursionError:
        pass
    return imports


def _check_call_arity_mismatch(
    call_node: ast.Call,
    target_sym: _PySymbolInfo | None,
    change_kind: str,
) -> tuple[bool, str]:
    """Verify whether an AST call site is incompatible with the target symbol's updated signature."""
    if change_kind == "removed":
        return True, "Symbol was removed in target revision; call site will raise NameError or AttributeError."
    if target_sym is None or target_sym.symbol_kind not in ("function", "async_function", "method"):
        return False, ""

    has_starred = any(isinstance(a, ast.Starred) for a in call_node.args)
    has_kwargs_unpack = any(kw.arg is None for kw in call_node.keywords)
    pos_passed = len(call_node.args)
    kw_passed = {kw.arg for kw in call_node.keywords if kw.arg is not None}

    pos_params = [p for p in target_sym.params if p.kind in ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")]
    kw_only_params = [p for p in target_sym.params if p.kind == "KEYWORD_ONLY"]
    has_varargs = any(p.kind == "VAR_POSITIONAL" for p in target_sym.params)
    has_varkw = any(p.kind == "VAR_KEYWORD" for p in target_sym.params)

    # Check too many positional arguments
    if not has_varargs and not has_starred and pos_passed > len(pos_params):
        return (
            True,
            f"Call passes {pos_passed} positional argument(s), but updated signature accepts at most {len(pos_params)}.",
        )

    # Check unknown keyword arguments
    if not has_varkw and kw_passed:
        valid_kw_names = {
            p.name for p in target_sym.params if p.kind in ("POSITIONAL_OR_KEYWORD", "KEYWORD_ONLY")
        }
        invalid_kw = sorted(kw_passed - valid_kw_names)
        if invalid_kw:
            return (
                True,
                f"Call passes unsupported/removed keyword argument(s) {invalid_kw} not in updated signature.",
            )

    # Check missing required parameters
    if not has_starred and not has_kwargs_unpack:
        missing_req: list[str] = []
        for idx, p in enumerate(pos_params):
            if not p.has_default:
                satisfied_by_pos = idx < pos_passed
                satisfied_by_kw = p.kind == "POSITIONAL_OR_KEYWORD" and p.name in kw_passed
                if not (satisfied_by_pos or satisfied_by_kw):
                    missing_req.append(p.name)
        for p in kw_only_params:
            if not p.has_default and p.name not in kw_passed:
                missing_req.append(p.name)
        if missing_req:
            return (
                True,
                f"Call passes {pos_passed} positional arg(s) and keywords {sorted(kw_passed)}, missing required parameter(s) {missing_req}.",
            )

    return False, ""


def _analyze_py_recursion_bugs(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    sym_info: _PySymbolInfo,
    is_method: bool,
    module_top_names: set[str],
) -> None:
    """Detect recursive self-calls, recursive arity mismatches, unqualified method self-reference, and infinite recursion without base case."""
    stmts = list(func_node.body)
    if (
        stmts
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]
    if not stmts:
        return

    param_names = {p.name for p in sym_info.params}
    local_store_names: set[str] = set(param_names) | {"self", "cls"}
    has_yield = False

    # Iterative stack traversal avoiding nested FunctionDef / ClassDef scopes
    stack: list[ast.AST] = list(reversed(stmts))
    body_calls: list[ast.Call] = []
    while stack:
        curr = stack.pop()
        if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local_store_names.add(curr.name)
            continue
        if isinstance(curr, (ast.Yield, ast.YieldFrom)):
            has_yield = True
        if isinstance(curr, ast.Name) and isinstance(curr.ctx, ast.Store):
            local_store_names.add(curr.id)
        if isinstance(curr, ast.Call):
            body_calls.append(curr)
        try:
            children = list(ast.iter_child_nodes(curr))
            stack.extend(reversed(children))
        except RecursionError:
            break

    def _is_direct_self_call(call_node: ast.Call) -> bool:
        if not is_method:
            return (
                isinstance(call_node.func, ast.Name)
                and call_node.func.id == sym_info.short_name
                and sym_info.short_name not in param_names
            )
        return (
            isinstance(call_node.func, ast.Attribute)
            and isinstance(call_node.func.value, ast.Name)
            and call_node.func.value.id in ("self", "cls")
            and call_node.func.attr == sym_info.short_name
        )

    for call in body_calls:
        lineno = getattr(call, "lineno", sym_info.start_line)
        if _is_direct_self_call(call):
            sym_info.is_recursive = True
            arity_broken, mismatch_msg = _check_call_arity_mismatch(call, sym_info, "signature_changed")
            if arity_broken:
                sym_info.recursive_arity_mismatches.append(
                    f"Recursive call to '{sym_info.qualified_name}' at line {lineno} has incompatible arguments ({mismatch_msg})"
                )
        elif (
            is_method
            and isinstance(call.func, ast.Name)
            and call.func.id == sym_info.short_name
            and sym_info.short_name not in ("__init__", "__call__")
            and sym_info.short_name not in module_top_names
            and sym_info.short_name not in local_store_names
        ):
            sym_info.is_recursive = True
            sym_info.unqualified_method_self_calls.append(
                f"Method '{sym_info.qualified_name}' calls bare '{sym_info.short_name}(...)' without 'self.' prefix at line {lineno} (will raise NameError at runtime)."
            )

    if not sym_info.is_recursive or has_yield:
        return

    # Check if a self-call is executed unconditionally prior to any conditional branch / base case
    _GUARD_NODES = (
        ast.If,
        ast.Match,
        ast.Try,
        ast.While,
        ast.For,
        ast.AsyncFor,
        ast.IfExp,
        ast.BoolOp,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
    )

    def _has_unguarded_self_call(root_node: ast.AST) -> bool:
        sub_stack: list[ast.AST] = [root_node]
        while sub_stack:
            n = sub_stack.pop()
            if isinstance(n, _GUARD_NODES):
                continue
            if isinstance(n, ast.Call) and _is_direct_self_call(n):
                return True
            sub_stack.extend(ast.iter_child_nodes(n))
        return False

    for stmt in stmts:
        if isinstance(stmt, ast.If):
            if _has_unguarded_self_call(stmt.test):
                sym_info.has_unconditional_recursion = True
            break
        if isinstance(stmt, ast.Match):
            if _has_unguarded_self_call(stmt.subject):
                sym_info.has_unconditional_recursion = True
            break
        if isinstance(stmt, (ast.Try, ast.While, ast.For, ast.AsyncFor, ast.Raise)):
            break
        if _has_unguarded_self_call(stmt):
            sym_info.has_unconditional_recursion = True
            break
        if isinstance(stmt, ast.Return):
            break


def _symbol_info_to_json(info: _PySymbolInfo) -> dict:
    data = asdict(info)
    data["raised_exceptions"] = sorted(info.raised_exceptions)
    data["none_guarded_params"] = sorted(info.none_guarded_params)
    return data


def _symbol_info_from_json(data: dict) -> _PySymbolInfo:
    payload = dict(data)
    payload["params"] = [_PyParamInfo(**p) for p in payload.get("params", [])]
    payload["raised_exceptions"] = set(payload.get("raised_exceptions", []))
    payload["none_guarded_params"] = set(payload.get("none_guarded_params", []))
    return _PySymbolInfo(**payload)


def _parse_python_symbols(
    source: str,
    file_path: str = "module.py",
    init_reexports: set[str] | None = None,
) -> dict[str, _PySymbolInfo]:
    """Cache-aware wrapper around the Python symbol parser (cache is opt-in)."""
    cache = get_active_cache()
    if cache is None:
        return _parse_python_symbols_uncached(source, file_path=file_path, init_reexports=init_reexports)
    extra = ",".join(sorted(init_reexports)) if init_reexports else ""
    key = compute_cache_key("py", file_path, source, extra)
    cached = cache.get(key)
    if isinstance(cached, dict):
        try:
            return {name: _symbol_info_from_json(item) for name, item in cached.items()}
        except (TypeError, ValueError, KeyError, AttributeError):
            pass
    result = _parse_python_symbols_uncached(source, file_path=file_path, init_reexports=init_reexports)
    cache.put(key, {name: _symbol_info_to_json(info) for name, info in result.items()})
    return result


def _parse_python_symbols_uncached(
    source: str,
    file_path: str = "module.py",
    init_reexports: set[str] | None = None,
) -> dict[str, _PySymbolInfo]:
    """Parse public Python functions, classes, methods, enums, and constants from source code."""
    try:
        tree = _parse_py_ast_quietly(source)
    except (SyntaxError, RecursionError, MemoryError):
        return {}

    dunder_all = _extract_dunder_all(tree)
    module_imports = _extract_py_imports(tree)
    builtin_names = set(dir(__builtins__)) if isinstance(__builtins__, dict) else set(dir(__builtins__))
    module_top_names: set[str] = set(module_imports.keys()) | builtin_names
    for top_node in tree.body:
        if isinstance(top_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_top_names.add(top_node.name)
        elif isinstance(top_node, ast.Assign):
            for t in top_node.targets:
                if isinstance(t, ast.Name):
                    module_top_names.add(t.id)
        elif isinstance(top_node, ast.AnnAssign) and isinstance(top_node.target, ast.Name):
            module_top_names.add(top_node.target.id)

    symbols: dict[str, _PySymbolInfo] = {}

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                continue
            is_async = isinstance(node, ast.AsyncFunctionDef)
            decs = [d for d in (_unparse_safe(dec) for dec in node.decorator_list) if d]
            params = _extract_py_params(node.args, is_method=False)
            ret = _unparse_safe(node.returns)
            sig = _format_py_signature(node.name, params, ret, decs, is_async=is_async)
            is_pub, pub_reason = _determine_py_export_exposure(node.name, file_path, dunder_all, init_reexports)
            sym_obj = _PySymbolInfo(
                qualified_name=node.name,
                short_name=node.name,
                symbol_kind="async_function" if is_async else "function",
                start_line=getattr(node, "lineno", 1),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                signature_str=sig,
                params=params,
                return_annotation=ret,
                decorators=decs,
                raised_exceptions=_extract_raised_exceptions(node),
                none_guarded_params=_extract_none_guarded_params(node),
                body_ast_dump=_compute_body_ast_dump(node),
                is_public_export=is_pub,
                export_reason=pub_reason,
            )
            _analyze_py_recursion_bugs(node, sym_obj, is_method=False, module_top_names=module_top_names)
            symbols[node.name] = sym_obj
        elif isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            bases = [b for b in (_unparse_safe(base) for base in node.bases) if b]
            decs = [d for d in (_unparse_safe(dec) for dec in node.decorator_list) if d]
            base_sig = f"({', '.join(bases)})" if bases else ""
            dec_prefix = "".join(f"@{d} " for d in decs) if decs else ""
            is_enum = _is_enum_class(bases)
            is_pub, pub_reason = _determine_py_export_exposure(node.name, file_path, dunder_all, init_reexports)

            enum_members: dict[str, str] = {}
            if is_enum:
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for t in item.targets:
                            if isinstance(t, ast.Name) and not t.id.startswith("_"):
                                enum_members[t.id] = _unparse_safe(item.value) or ""
                    elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        if not item.target.id.startswith("_") and item.value is not None:
                            enum_members[item.target.id] = _unparse_safe(item.value) or ""

            cls_sig = f"{dec_prefix}class {node.name}{base_sig}"
            if is_enum and enum_members:
                members_preview = ", ".join(f"{k}={v}" for k, v in list(enum_members.items())[:8])
                cls_sig = f"{cls_sig} [{members_preview}]"

            symbols[node.name] = _PySymbolInfo(
                qualified_name=node.name,
                short_name=node.name,
                symbol_kind="enum" if is_enum else "class",
                start_line=getattr(node, "lineno", 1),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                signature_str=cls_sig,
                decorators=decs,
                bases=bases,
                enum_members=enum_members,
                is_public_export=is_pub,
                export_reason=pub_reason,
            )
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name.startswith("_") and item.name not in ("__init__", "__call__"):
                        continue
                    is_async_m = isinstance(item, ast.AsyncFunctionDef)
                    m_decs = [d for d in (_unparse_safe(dec) for dec in item.decorator_list) if d]
                    is_static = any("staticmethod" in d for d in m_decs)
                    m_params = _extract_py_params(item.args, is_method=not is_static)
                    m_ret = _unparse_safe(item.returns)
                    qname = f"{node.name}.{item.name}"
                    m_sig = _format_py_signature(qname, m_params, m_ret, m_decs, is_async=is_async_m)
                    m_body_dump = _compute_body_ast_dump(item)

                    is_setter_or_deleter = any(d.endswith((".setter", ".deleter")) for d in m_decs)
                    if qname in symbols and is_setter_or_deleter:
                        qname_sub = (
                            f"{qname}.setter"
                            if any(d.endswith(".setter") for d in m_decs)
                            else f"{qname}.deleter"
                        )
                        sub_sym = _PySymbolInfo(
                            qualified_name=qname_sub,
                            short_name=f"{item.name}.setter",
                            symbol_kind="method",
                            start_line=getattr(item, "lineno", 1),
                            end_line=getattr(item, "end_lineno", getattr(item, "lineno", 1)),
                            signature_str=m_sig,
                            params=m_params,
                            return_annotation=m_ret,
                            decorators=m_decs,
                            raised_exceptions=_extract_raised_exceptions(item),
                            none_guarded_params=_extract_none_guarded_params(item),
                            body_ast_dump=m_body_dump,
                            is_public_export=is_pub,
                            export_reason=pub_reason,
                        )
                        _analyze_py_recursion_bugs(item, sub_sym, is_method=not is_static, module_top_names=module_top_names)
                        symbols[qname_sub] = sub_sym
                        continue

                    m_sym = _PySymbolInfo(
                        qualified_name=qname,
                        short_name=item.name,
                        symbol_kind="method",
                        start_line=getattr(item, "lineno", 1),
                        end_line=getattr(item, "end_lineno", getattr(item, "lineno", 1)),
                        signature_str=m_sig,
                        params=m_params,
                        return_annotation=m_ret,
                        decorators=m_decs,
                        raised_exceptions=_extract_raised_exceptions(item),
                        none_guarded_params=_extract_none_guarded_params(item),
                        body_ast_dump=m_body_dump,
                        is_public_export=is_pub,
                        export_reason=pub_reason,
                    )
                    _analyze_py_recursion_bugs(item, m_sym, is_method=not is_static, module_top_names=module_top_names)
                    symbols[qname] = m_sym
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if (
                    isinstance(t, ast.Name)
                    and len(t.id) >= 2
                    and t.id.isupper()
                    and not t.id.startswith("_")
                ):
                    val_str = _unparse_safe(node.value) or "..."
                    is_pub, pub_reason = _determine_py_export_exposure(t.id, file_path, dunder_all, init_reexports)
                    symbols[t.id] = _PySymbolInfo(
                        qualified_name=t.id,
                        short_name=t.id,
                        symbol_kind="constant",
                        start_line=getattr(node, "lineno", 1),
                        end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                        signature_str=f"{t.id} = {val_str}",
                        is_public_export=is_pub,
                        export_reason=pub_reason,
                    )
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            t_id = node.target.id
            if len(t_id) >= 2 and t_id.isupper() and not t_id.startswith("_"):
                ann_str = _unparse_safe(node.annotation) or ""
                val_str = _unparse_safe(node.value) if node.value is not None else None
                sig_c = f"{t_id}: {ann_str}" + (f" = {val_str}" if val_str is not None else "")
                is_pub, pub_reason = _determine_py_export_exposure(t_id, file_path, dunder_all, init_reexports)
                symbols[t_id] = _PySymbolInfo(
                    qualified_name=t_id,
                    short_name=t_id,
                    symbol_kind="constant",
                    start_line=getattr(node, "lineno", 1),
                    end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                    signature_str=sig_c,
                    is_public_export=is_pub,
                    export_reason=pub_reason,
                )

    return symbols


_PY_PEP585_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:typing\.)?Dict\b"), "dict"),
    (re.compile(r"\b(?:typing\.)?List\b"), "list"),
    (re.compile(r"\b(?:typing\.)?Set\b"), "set"),
    (re.compile(r"\b(?:typing\.)?FrozenSet\b"), "frozenset"),
    (re.compile(r"\b(?:typing\.)?Tuple\b"), "tuple"),
    (re.compile(r"\b(?:typing\.)?Type\b"), "type"),
    (
        re.compile(
            r"\btyping\.(Optional|Union|Any|Callable|Iterable|Iterator|Mapping|Sequence|MutableMapping|MutableSequence)\b"
        ),
        r"\1",
    ),
)


def _canonicalize_py_annotation(ann: str | None) -> str | None:
    """Normalize PEP 585 / typing-module equivalents (Dict -> dict, etc.) in Python annotations."""
    if ann is None:
        return None
    s = " ".join(ann.split()).strip()
    if not s:
        return s
    for pat, repl in _PY_PEP585_REPLACEMENTS:
        s = pat.sub(repl, s)
    return s


def _strip_optional_type(ann: str | None) -> str | None:
    """Normalize outer `Optional[T]`, `T | None`, or `None | T` into inner `T` when present."""
    if not ann:
        return None
    s = _canonicalize_py_annotation(ann) or ""
    if s.startswith("Optional[") and s.endswith("]"):
        return s[len("Optional[") : -1].strip()
    if "|" in s:
        parts = [p.strip() for p in s.split("|") if p.strip() != "None"]
        if len(parts) == 1:
            return parts[0]
    return s


def _compare_python_symbol(
    file_path: str,
    old_sym: _PySymbolInfo,
    new_sym: _PySymbolInfo,
) -> list[tuple[str, bool, str, str]]:
    """Return list of (change_kind, is_breaking_candidate, severity, details) for a symbol pair."""
    findings: list[tuple[str, bool, str, str]] = []

    if old_sym.symbol_kind == "constant" and new_sym.symbol_kind == "constant":
        if old_sym.signature_str != new_sym.signature_str:
            findings.append(
                (
                    "signature_changed",
                    True,
                    "medium",
                    f"Public constant '{old_sym.qualified_name}' changed from `{old_sym.signature_str}` to `{new_sym.signature_str}`.",
                )
            )
        return findings

    if old_sym.symbol_kind in ("class", "enum") and new_sym.symbol_kind in ("class", "enum"):
        if old_sym.bases != new_sym.bases:
            old_base_short = {b.split(".")[-1] for b in old_sym.bases}
            new_base_short = {b.split(".")[-1] for b in new_sym.bases}
            is_strenum_migration = (
                ("str" in old_base_short and "Enum" in old_base_short and "StrEnum" in new_base_short)
                or ("StrEnum" in old_base_short and "str" in new_base_short and "Enum" in new_base_short)
            )
            if is_strenum_migration:
                findings.append(
                    (
                        "base_class_changed",
                        True,
                        "high",
                        f"Enum '{old_sym.qualified_name}' base classes changed from {old_sym.bases} to {new_sym.bases} (griffe#501: str(member) formatting semantics change between (str, Enum) and StrEnum).",
                    )
                )
            else:
                findings.append(
                    (
                        "base_class_changed",
                        True,
                        "medium",
                        f"Class '{old_sym.qualified_name}' base classes changed from {old_sym.bases} to {new_sym.bases} (potential isinstance/inheritance break).",
                    )
                )
        if set(old_sym.decorators) != set(new_sym.decorators):
            findings.append(
                (
                    "decorator_changed",
                    True,
                    "medium",
                    f"Class '{old_sym.qualified_name}' decorators changed from {old_sym.decorators} to {new_sym.decorators}.",
                )
            )
        if old_sym.enum_members or new_sym.enum_members:
            removed_members = [m for m in old_sym.enum_members if m not in new_sym.enum_members]
            if removed_members:
                findings.append(
                    (
                        "signature_changed",
                        True,
                        "high",
                        f"Removed Enum member(s) {removed_members} from '{old_sym.qualified_name}'.",
                    )
                )
            changed_vals = [
                f"{m} ({old_sym.enum_members[m]} -> {new_sym.enum_members[m]})"
                for m in old_sym.enum_members
                if m in new_sym.enum_members and old_sym.enum_members[m] != new_sym.enum_members[m]
            ]
            if changed_vals:
                findings.append(
                    (
                        "signature_changed",
                        True,
                        "medium",
                        f"Enum member value(s) changed in '{old_sym.qualified_name}': {', '.join(changed_vals)}.",
                    )
                )
        return findings

    # Compare function/method parameters
    old_by_name = {p.name: p for p in old_sym.params if p.kind not in ("VAR_POSITIONAL", "VAR_KEYWORD")}
    new_by_name = {p.name: p for p in new_sym.params if p.kind not in ("VAR_POSITIONAL", "VAR_KEYWORD")}
    has_new_varargs = any(p.kind == "VAR_POSITIONAL" for p in new_sym.params)
    has_new_kwargs = any(p.kind == "VAR_KEYWORD" for p in new_sym.params)

    removed_params = [old_by_name[name] for name in old_by_name if name not in new_by_name]
    if removed_params:
        unabsorbed: list[str] = []
        for rp in removed_params:
            absorbed = (
                (rp.kind == "POSITIONAL_ONLY" and has_new_varargs)
                or (rp.kind == "KEYWORD_ONLY" and has_new_kwargs)
                or (rp.kind == "POSITIONAL_OR_KEYWORD" and has_new_varargs and has_new_kwargs)
            )
            if not absorbed:
                unabsorbed.append(rp.name)
        removed_names = [rp.name for rp in removed_params]
        if not unabsorbed:
            findings.append(
                (
                    "signature_changed",
                    False,
                    "low",
                    f"Parameters {removed_names} removed from '{old_sym.qualified_name}', but absorbed by variadic parameters.",
                )
            )
        else:
            findings.append(
                (
                    "signature_changed",
                    True,
                    "high",
                    f"Removed parameter(s) {unabsorbed} from '{old_sym.qualified_name}' without variadic absorption.",
                )
            )

    added_required = [
        p.name
        for p in new_sym.params
        if p.name not in old_by_name and not p.has_default and p.kind not in ("VAR_POSITIONAL", "VAR_KEYWORD")
    ]
    if added_required:
        findings.append(
            (
                "signature_changed",
                True,
                "high",
                f"Added required parameter(s) {added_required} without default values to '{old_sym.qualified_name}'.",
            )
        )

    added_optional = [
        p.name
        for p in new_sym.params
        if p.name not in old_by_name and p.has_default and p.kind not in ("VAR_POSITIONAL", "VAR_KEYWORD")
    ]

    # Check common parameters for reordered or index-shifted positional parameters (BUG-030), lost defaults, default=None guard (griffe#469), or kind changes
    old_pos_order = [p.name for p in old_sym.params if p.kind in ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")]
    new_pos_order = [p.name for p in new_sym.params if p.kind in ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")]
    old_pos_idx = {name: idx for idx, name in enumerate(old_pos_order)}
    new_pos_idx = {name: idx for idx, name in enumerate(new_pos_order)}
    common_pos_old = [n for n in old_pos_order if n in new_pos_idx]
    common_pos_new = [n for n in new_pos_order if n in old_pos_idx]
    if common_pos_old != common_pos_new:
        findings.append(
            (
                "signature_changed",
                True,
                "high",
                f"Positional parameter order changed in '{old_sym.qualified_name}' from {common_pos_old} to {common_pos_new}.",
            )
        )
    else:
        shifted_pos = [
            f"{n} (index {old_pos_idx[n]} -> {new_pos_idx[n]})"
            for n in common_pos_old
            if old_pos_idx[n] != new_pos_idx[n]
        ]
        if shifted_pos:
            findings.append(
                (
                    "signature_changed",
                    True,
                    "high",
                    f"Surviving positional parameter(s) {', '.join(shifted_pos)} shifted position in '{old_sym.qualified_name}' due to parameter insertion; existing positional callers will bind arguments to different parameters.",
                )
            )

    for name, old_p in old_by_name.items():
        if name not in new_by_name:
            continue
        new_p = new_by_name[name]
        if old_p.has_default and not new_p.has_default:
            findings.append(
                (
                    "signature_changed",
                    True,
                    "high",
                    f"Parameter '{name}' in '{old_sym.qualified_name}' lost its default value ({old_p.default_repr}) and is now required.",
                )
            )
        elif old_p.has_default and new_p.has_default and old_p.default_repr != new_p.default_repr:
            if new_p.default_repr == "None" and name in new_sym.none_guarded_params:
                findings.append(
                    (
                        "signature_changed",
                        False,
                        "low",
                        f"Parameter '{name}' default changed from {old_p.default_repr} to None in '{old_sym.qualified_name}', but function body contains a None-fallback guard (griffe#469 pattern).",
                    )
                )
            else:
                findings.append(
                    (
                        "signature_changed",
                        True,
                        "medium",
                        f"Default value for parameter '{name}' in '{old_sym.qualified_name}' changed from {old_p.default_repr} to {new_p.default_repr}.",
                    )
                )
        if old_p.kind != new_p.kind:
            # Relaxing trailing KEYWORD_ONLY -> POSITIONAL_OR_KEYWORD preserves all existing kw callers;
            # mutating '/' (POSITIONAL_ONLY boundary) stays flagged per API contract.
            is_widening = (
                old_p.kind == "KEYWORD_ONLY"
                and new_p.kind == "POSITIONAL_OR_KEYWORD"
            )
            findings.append(
                (
                    "signature_changed",
                    not is_widening,
                    "low" if is_widening else "medium",
                    f"Parameter '{name}' kind in '{old_sym.qualified_name}' changed from {old_p.kind} to {new_p.kind}"
                    + (" (backward-compatible widening)." if is_widening else "."),
                )
            )

    if added_optional and not findings:
        findings.append(
            (
                "signature_changed",
                False,
                "low",
                f"Added backward-compatible optional parameter(s) {added_optional} with default values to '{old_sym.qualified_name}'.",
            )
        )

    # Check return type annotation change (Optional[T] -> T is backward-compatible narrowing; PEP 585 aliases ignored)
    canon_old_ret = _canonicalize_py_annotation(old_sym.return_annotation)
    canon_new_ret = _canonicalize_py_annotation(new_sym.return_annotation)
    if canon_old_ret != canon_new_ret and canon_old_ret is not None:
        old_inner = _strip_optional_type(canon_old_ret)
        new_inner = _strip_optional_type(canon_new_ret)
        is_optional_narrowing = (
            old_inner is not None
            and old_inner != canon_old_ret
            and canon_new_ret == old_inner
        )
        _ = new_inner
        findings.append(
            (
                "return_type_changed",
                not is_optional_narrowing,
                "low" if is_optional_narrowing else "medium",
                f"Return type annotation of '{old_sym.qualified_name}' changed from '{old_sym.return_annotation}' to '{new_sym.return_annotation}'"
                + (" (non-Optional narrowing)." if is_optional_narrowing else "."),
            )
        )

    # Check decorator removal/change (ignore static-typechecker @override markers)
    old_decs = [d for d in old_sym.decorators if d not in ("override", "typing.override")]
    new_decs = [d for d in new_sym.decorators if d not in ("override", "typing.override")]
    if old_decs != new_decs:
        findings.append(
            (
                "decorator_changed",
                True,
                "medium",
                f"Decorators on '{old_sym.qualified_name}' changed from {old_decs} to {new_decs}.",
            )
        )

    # Check newly raised exceptions in function body (griffe#498 gap)
    newly_raised = sorted(new_sym.raised_exceptions - old_sym.raised_exceptions)
    if newly_raised:
        findings.append(
            (
                "exception_raised_added",
                True,
                "medium",
                f"Function '{old_sym.qualified_name}' now raises new exception type(s) {newly_raised} not raised in base revision.",
            )
        )

    # Check recursive function bugs (gemma:latest AST bug patterns: wrong recursive arg, missing base case, unqualified method self-reference)
    if new_sym.recursive_arity_mismatches:
        findings.append(
            (
                "signature_changed",
                True,
                "high",
                f"Recursive self-call bug in '{new_sym.qualified_name}': {new_sym.recursive_arity_mismatches[0]}",
            )
        )

    if new_sym.has_unconditional_recursion and not old_sym.has_unconditional_recursion:
        findings.append(
            (
                "exception_raised_added",
                True,
                "high",
                f"Infinite recursion bug in '{new_sym.qualified_name}': recursive self-call executes unconditionally without a preceding base-case guard (will raise RecursionError).",
            )
        )

    if new_sym.unqualified_method_self_calls and not old_sym.unqualified_method_self_calls:
        findings.append(
            (
                "exception_raised_added",
                True,
                "high",
                f"Incorrect self-reference in recursive method '{new_sym.qualified_name}': {new_sym.unqualified_method_self_calls[0]}",
            )
        )

    return findings


SUPPORTED_NON_PY_CODE_EXTS = (
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
    ".go", ".rs", ".java", ".kt", ".scala", ".cs", ".rb", ".php", ".swift",
)
SUPPORTED_ALL_CODE_EXTS = (".py", *SUPPORTED_NON_PY_CODE_EXTS)

_TS_EXPORT_FUNC_RE = re.compile(
    r"^\s*export\s+(?:declare\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<name>[A-Za-z0-9_$]+)(?:<[^>]*>)?\s*\((?P<params>[^)]*)\)(?:\s*:\s*(?P<ret>[^{;\n]+))?",
    re.MULTILINE,
)
_TS_EXPORT_ARROW_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?(?:<[^>]*>)?\s*\((?P<params>[^)]*)\)(?:\s*:\s*(?P<ret>[^{;=>\n]+))?\s*=>",
    re.MULTILINE,
)
_TS_EXPORT_CLASS_RE = re.compile(
    r"^\s*export\s+(?:declare\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(?P<name>[A-Za-z0-9_$]+)(?:<[^>]*>)?(?:\s+extends\s+(?P<base>[A-Za-z0-9_$.<>]+))?",
    re.MULTILINE,
)
_TS_CLASS_METHOD_RE = re.compile(
    r"^\s+(?:public\s+|protected\s+)?(?:static\s+)?(?:async\s+)?(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)(?:<[^>]*>)?\s*\((?P<params>[^;{}()]*)\)(?:\s*:\s*(?P<ret>[^{;\n]+))?\s*\{",
    re.MULTILINE,
)
_TS_EXPORT_TYPE_RE = re.compile(
    r"^\s*export\s+(?:declare\s+)?(?P<kind>interface|type|enum)\s+(?P<name>[A-Za-z0-9_$]+)(?:[<={\s])",
    re.MULTILINE,
)
_JS_TOP_FUNC_RE = re.compile(
    r"^\s*(?:async\s+)?function\s*\*?\s*(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\((?P<params>[^)]*)\)",
    re.MULTILINE,
)
_GO_FUNC_RE = re.compile(
    r"^func\s+(?:\((?P<recv>[^)]+)\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)\s*(?P<ret>[^{;\n]*)",
    re.MULTILINE,
)
_GO_TYPE_RE = re.compile(
    r"^type\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+(?P<kind>struct|interface)\b",
    re.MULTILINE,
)
_RUST_FN_RE = re.compile(
    r"^\s*(?P<vis>pub(?:\([^)]+\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:<[^>]*>)?\s*\((?P<params>[^)]*)\)(?:\s*->\s*(?P<ret>[^{;\n]+))?",
    re.MULTILINE,
)
_RUST_TYPE_RE = re.compile(
    r"^\s*(?P<vis>pub(?:\([^)]+\))?\s+)?(?P<kind>struct|enum|trait)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
_CPP_CLASS_RE = re.compile(
    r"^\s*(?:template\s*<[^>]*>\s*)?(?P<kind>class|struct|enum(?:\s+class)?)\s+(?:[A-Z0-9_]+\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*(?P<base>[^{;]+))?\{",
    re.MULTILINE,
)
_CPP_FUNC_RE = re.compile(
    r"^\s*(?:template\s*<[^>]*>\s*)?(?:(?:inline|constexpr|consteval|static|virtual|explicit|friend|extern|[A-Z0-9_]+)\s+)*(?P<ret>[A-Za-z_][A-Za-z0-9_:<>*,&\s]*\s+)(?P<name>[A-Za-z_][A-Za-z0-9_:]*)\s*\((?P<params>[^;{}()]*)\)\s*(?:const\s*)?(?:noexcept(?:\([^)]*\))?\s*)?(?:override\s*|final\s*)*(?:->\s*[^{;\n]+)?\s*(?=\{)",
    re.MULTILINE,
)
_JAVA_CS_CLASS_RE = re.compile(
    r"^\s*(?:public|protected|private|internal)?\s*(?:abstract\s+|final\s+|static\s+|sealed\s+|partial\s+|open\s+|data\s+|enum\s+)*(?P<kind>class|interface|enum|record|trait|object)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
_JAVA_CS_METHOD_RE = re.compile(
    r"^\s*(?P<mods>(?:(?:public|protected|private|internal|static|final|abstract|synchronized|virtual|override|async|sealed|readonly|extern|unsafe|new|partial|native|strictfp|default)\s+)*)(?:<[^>]+>\s+)?(?P<ret>[A-Za-z0-9_<>\[\].,?\s]+?)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)",
    re.MULTILINE,
)
_KOTLIN_SCALA_FUNC_RE = re.compile(
    r"^\s*(?P<mods>(?:(?:public|protected|private|internal|open|override|final|abstract|suspend|inline|infix|operator|tailrec|external)\s+)*)(?:fun|def)\s+(?:<[^>]+>\s+|\[[^\]]+\]\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)(?:\s*:\s*(?P<ret>[A-Za-z0-9_<>\[\].,?\s*|]+?))?(?:\s*[={]|\s*$)",
    re.MULTILINE,
)
_RB_PHP_SWIFT_FUNC_RE = re.compile(
    r"^\s*(?P<mods>(?:(?:public|protected|private|internal|open|fileprivate|static|final|abstract|async|override|mutating)\s+)*)(?:def|function|func)\s+(?P<name>(?:self\.)?[A-Za-z_][A-Za-z0-9_?!]*)\s*(?:\((?P<params>[^)]*)\))?(?:\s*(?:async\s+)?(?::|->)\s*(?P<ret>[^{;\n]+))?",
    re.MULTILINE,
)
_RB_PHP_SWIFT_CLASS_RE = re.compile(
    r"^\s*(?P<mods>(?:(?:public|protected|private|internal|open|final|abstract|readonly)\s+)*)(?P<kind>class|module|interface|trait|struct|protocol|enum)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
_CPP_CONTROL_KEYWORDS = {
    "if", "else", "for", "while", "switch", "catch", "return", "sizeof",
    "alignof", "decltype", "static_assert", "assert", "defined", "elif",
    "pragma", "include", "define", "undef", "typename", "template",
    "new", "delete", "throw", "try", "namespace", "using",
}
_JS_CONTROL_KEYWORDS = {
    "if", "else", "for", "while", "switch", "catch", "return", "function",
    "constructor", "super", "import", "export", "typeof", "instanceof", "await",
}


def _parse_multilang_symbols_rich_fallback(
    source: str,
    file_path: str,
) -> dict[str, ParsedMultiLangSymbol]:
    """Hardened pure-Python structural symbol extractor with canonicalized modifiers & visibility."""
    family = get_language_family(file_path)
    symbols: dict[str, ParsedMultiLangSymbol] = {}

    def _build_sym(
        qname: str,
        short: str,
        owner: str | None,
        skind: str,
        line_no: int,
        vis: str,
        mods: frozenset[str],
        raw_params: str,
        ret_type: str | None,
        sig: str,
        has_export: bool = False,
    ) -> ParsedMultiLangSymbol:
        params, ntypes, req_cnt = _parse_params_from_raw(raw_params, family)
        is_pub, exp_reason = compute_multilang_visibility(
            family=family,
            file_path=file_path,
            short_name=short,
            visibility=vis,
            modifiers=mods,
            owner_type=owner,
            has_export=has_export,
        )
        return ParsedMultiLangSymbol(
            qualified_name=qname,
            short_name=short,
            owner_type=owner,
            symbol_kind=skind,
            start_line=line_no,
            end_line=line_no,
            visibility=vis,
            is_public_api=is_pub,
            export_reason=exp_reason,
            modifiers=mods,
            params=params,
            normalized_param_types=ntypes,
            required_param_count=req_cnt,
            return_type=ret_type,
            signature_str=sig,
            parser_backend="structural_fallback",
        )

    if family == "ts_js":
        for match in _TS_EXPORT_FUNC_RE.finditer(source):
            name = match.group("name")
            params_raw = " ".join(match.group("params").split())
            ret_raw = " ".join((match.group("ret") or "").split()) or None
            line_no = source.count("\n", 0, match.start()) + 1
            sig = f"export function {name}({params_raw})" + (f": {ret_raw}" if ret_raw else "")
            symbols[name] = _build_sym(
                name, name, None, "function", line_no, "public", frozenset({"export"}), params_raw, ret_raw, sig, has_export=True
            )
        for match in _TS_EXPORT_ARROW_RE.finditer(source):
            name = match.group("name")
            if name in symbols or name.startswith("_"):
                continue
            params_raw = " ".join(match.group("params").split())
            ret_raw = " ".join((match.group("ret") or "").split()) or None
            line_no = source.count("\n", 0, match.start()) + 1
            is_exp = "export" in match.group(0).split("=")[0]
            sig = f"{'export ' if is_exp else ''}const {name} = ({params_raw})" + (f": {ret_raw}" if ret_raw else "") + " =>"
            symbols[name] = _build_sym(
                name,
                name,
                None,
                "function",
                line_no,
                "public" if is_exp else "internal",
                frozenset({"export"}) if is_exp else frozenset(),
                params_raw,
                ret_raw,
                sig,
                has_export=is_exp,
            )
        for match in _TS_EXPORT_CLASS_RE.finditer(source):
            name = match.group("name")
            base = (match.group("base") or "").strip() or None
            line_no = source.count("\n", 0, match.start()) + 1
            sig = f"export class {name}" + (f" extends {base}" if base else "")
            symbols[name] = _build_sym(
                name, name, None, "class", line_no, "public", frozenset({"export"}), "", base, sig, has_export=True
            )
        for match in _TS_EXPORT_TYPE_RE.finditer(source):
            name = match.group("name")
            kind_raw = match.group("kind").lower()
            kind_name = "enum" if kind_raw == "enum" else "interface"
            line_no = source.count("\n", 0, match.start()) + 1
            sig = f"export {kind_raw} {name}"
            symbols[name] = _build_sym(
                name, name, None, kind_name, line_no, "public", frozenset({"export"}), "", None, sig, has_export=True
            )
        for match in _JS_TOP_FUNC_RE.finditer(source):
            name = match.group("name")
            if name in symbols or name in _JS_CONTROL_KEYWORDS or name.startswith("_"):
                continue
            params_raw = " ".join(match.group("params").split())
            line_no = source.count("\n", 0, match.start()) + 1
            sig = f"function {name}({params_raw})"
            symbols[name] = _build_sym(name, name, None, "function", line_no, "internal", frozenset(), params_raw, None, sig)
        for match in _TS_CLASS_METHOD_RE.finditer(source):
            name = match.group("name")
            if name in symbols or name in _JS_CONTROL_KEYWORDS or name.startswith(("_", "#")):
                continue
            params_raw = " ".join(match.group("params").split())
            ret_raw = " ".join((match.group("ret") or "").split()) or None
            line_no = source.count("\n", 0, match.start()) + 1
            sig = f"{name}({params_raw})" + (f": {ret_raw}" if ret_raw else "")
            symbols[name] = _build_sym(
                name, name, None, "method", line_no, "public", frozenset(), params_raw, ret_raw, sig, has_export="export " in source
            )
        return symbols

    if family == "go":
        for m in _GO_FUNC_RE.finditer(source):
            name = m.group("name")
            recv = (m.group("recv") or "").strip()
            params_raw = " ".join(m.group("params").split())
            ret_raw = " ".join((m.group("ret") or "").split()) or None
            line_no = source.count("\n", 0, m.start()) + 1
            qname = name
            recv_type = None
            if recv:
                recv_type = recv.split()[-1].lstrip("*").split("[", 1)[0]
                qname = f"{recv_type}.{name}"
            sig = f"func {f'({recv}) ' if recv else ''}{name}({params_raw})" + (f" {ret_raw}" if ret_raw else "")
            vis = "public" if name[:1].isupper() else "internal"
            symbols[qname] = _build_sym(
                qname, name, recv_type, "method" if recv else "function", line_no, vis, frozenset(), params_raw, ret_raw, sig
            )
        for m in _GO_TYPE_RE.finditer(source):
            name = m.group("name")
            kind_raw = m.group("kind")
            line_no = source.count("\n", 0, m.start()) + 1
            vis = "public" if name[:1].isupper() else "internal"
            symbols[name] = _build_sym(
                name, name, None, "interface" if kind_raw == "interface" else "class", line_no, vis, frozenset(), "", None, f"type {name} {kind_raw}"
            )
        return symbols

    if family == "rust":
        for m in _RUST_FN_RE.finditer(source):
            name = m.group("name")
            vis_raw = (m.group("vis") or "").strip()
            vis = "public" if vis_raw == "pub" else ("internal" if vis_raw.startswith("pub(") else "private")
            params_raw = " ".join(m.group("params").split())
            ret_raw = " ".join((m.group("ret") or "").split()) or None
            line_no = source.count("\n", 0, m.start()) + 1
            sig = f"{'pub ' if vis == 'public' else ''}fn {name}({params_raw})" + (f" -> {ret_raw}" if ret_raw else "")
            symbols[name] = _build_sym(
                name, name, None, "function", line_no, vis, frozenset({vis_raw}) if vis_raw else frozenset(), params_raw, ret_raw, sig
            )
        for m in _RUST_TYPE_RE.finditer(source):
            name = m.group("name")
            vis_raw = (m.group("vis") or "").strip()
            vis = "public" if vis_raw == "pub" else ("internal" if vis_raw.startswith("pub(") else "private")
            kind_raw = m.group("kind")
            kind_mapped = "enum" if kind_raw == "enum" else ("interface" if kind_raw == "trait" else "class")
            line_no = source.count("\n", 0, m.start()) + 1
            symbols[name] = _build_sym(
                name, name, None, kind_mapped, line_no, vis, frozenset(), "", None, f"{'pub ' if vis == 'public' else ''}{kind_raw} {name}"
            )
        return symbols

    if family == "c_cpp":
        cpp_src = _preprocess_cpp_export_macros(source)
        for m in _CPP_CLASS_RE.finditer(cpp_src):
            name = m.group("name")
            if name in _CPP_CONTROL_KEYWORDS or (name.isupper() and len(name) >= 3):
                continue
            kind_raw = " ".join(m.group("kind").split())
            base = " ".join((m.group("base") or "").split()) or None
            line_no = cpp_src.count("\n", 0, m.start()) + 1
            kind_mapped = "enum" if "enum" in kind_raw else "class"
            sig = f"{kind_raw} {name}" + (f" : {base}" if base else "")
            _store_symbol(symbols, _build_sym(name, name, None, kind_mapped, line_no, "public", frozenset(), "", base, sig))
        for m in _CPP_FUNC_RE.finditer(cpp_src):
            ret_raw = " ".join((m.group("ret") or "").split())
            ret_tokens = {tok.strip("*&") for tok in ret_raw.split()}
            name = m.group("name").strip()
            short_n = name.split("::")[-1]
            params_raw = " ".join(m.group("params").split())
            if (
                short_n in _CPP_CONTROL_KEYWORDS
                or bool(ret_tokens & _CPP_CONTROL_KEYWORDS)
                or short_n.startswith("~")
                or (short_n.isupper() and len(short_n) >= 3)
                or '"' in params_raw
                or "'" in params_raw
            ):
                continue
            line_no = cpp_src.count("\n", 0, m.start()) + 1
            mods_prefix = m.group(0)[: m.start("ret") - m.start()]
            mods, _ = normalize_modifiers_and_return(mods_prefix)
            if "static" in ret_tokens:
                mods = mods | {"static"}
            vis = "internal" if ("static" in mods or short_n.startswith("_")) else "public"
            owner = name.rsplit("::", 1)[0] if "::" in name else None
            sig = f"{name}({params_raw})"
            _store_symbol(
                symbols,
                _build_sym(
                    name,
                    short_n,
                    owner,
                    "method" if "::" in name else "function",
                    line_no,
                    vis,
                    mods,
                    params_raw,
                    normalize_type_expr(ret_raw) or None,
                    sig,
                ),
                allow_overload=True,
            )
        return symbols

    if family in ("csharp", "java", "kotlin", "scala"):
        default_vis = "public" if family in ("kotlin", "scala") else "internal"
        first_class: str | None = None
        class_spans: list[tuple[int, str, str]] = []
        for m in _JAVA_CS_CLASS_RE.finditer(source):
            name = m.group("name")
            if first_class is None:
                first_class = name
            kind_raw = m.group("kind").lower()
            kind_mapped = "enum" if kind_raw == "enum" else ("interface" if kind_raw in ("interface", "trait") else "class")
            line_no = source.count("\n", 0, m.start()) + 1
            cls_mods_prefix = m.group(0)[: m.start("kind") - m.start()]
            cls_mods, _ = normalize_modifiers_and_return(cls_mods_prefix)
            vis = resolve_visibility_from_modifiers(cls_mods, default_visibility=default_vis)
            class_spans.append((m.start(), name, vis))
            _store_symbol(
                symbols,
                _build_sym(name, name, None, kind_mapped, line_no, vis, cls_mods, "", None, f"{kind_raw} {name}"),
            )

        def _enclosing_class_info(pos: int) -> tuple[str | None, str]:
            owner_cls = first_class
            owner_vis = "public"
            for c_pos, c_name, c_vis in class_spans:
                if c_pos <= pos:
                    owner_cls = c_name
                    owner_vis = c_vis
                else:
                    break
            return owner_cls, owner_vis

        if family in ("kotlin", "scala"):
            for m in _KOTLIN_SCALA_FUNC_RE.finditer(source):
                name = m.group("name")
                if name in _CPP_CONTROL_KEYWORDS:
                    continue
                mods_raw = (m.group("mods") or "").strip()
                mods, _ = normalize_modifiers_and_return(mods_raw)
                vis = resolve_visibility_from_modifiers(mods, default_visibility=default_vis)
                owner_cls, owner_vis = _enclosing_class_info(m.start())
                if owner_vis in ("private", "internal") and vis in ("public", "protected"):
                    vis = owner_vis
                params_raw = " ".join(m.group("params").split())
                ret_raw = " ".join((m.group("ret") or "").split()) or None
                line_no = source.count("\n", 0, m.start()) + 1
                sorted_m = " ".join(sorted(mods))
                sig = f"{sorted_m + ' ' if sorted_m else ''}{name}({params_raw})" + (f": {ret_raw}" if ret_raw else "")
                _store_symbol(
                    symbols,
                    _build_sym(name, name, owner_cls, "method", line_no, vis, mods, params_raw, ret_raw, sig),
                    allow_overload=True,
                )
        else:
            for m in _JAVA_CS_METHOD_RE.finditer(source):
                name = m.group("name")
                if name in _CPP_CONTROL_KEYWORDS:
                    continue
                mods_and_ret = f"{m.group('mods') or ''} {m.group('ret')}"
                mods, pure_ret = normalize_modifiers_and_return(mods_and_ret)
                if pure_ret is None or any(tok in _CPP_CONTROL_KEYWORDS for tok in pure_ret.split()):
                    continue
                vis = resolve_visibility_from_modifiers(mods, default_visibility=default_vis)
                owner_cls, owner_vis = _enclosing_class_info(m.start())
                if owner_vis in ("private", "internal") and vis in ("public", "protected"):
                    vis = owner_vis
                params_raw = " ".join(m.group("params").split())
                line_no = source.count("\n", 0, m.start()) + 1
                sorted_m = " ".join(sorted(mods))
                sig = f"{sorted_m + ' ' if sorted_m else ''}{pure_ret} {name}({params_raw})"
                _store_symbol(
                    symbols,
                    _build_sym(name, name, owner_cls, "method", line_no, vis, mods, params_raw, pure_ret, sig),
                    allow_overload=True,
                )
        return symbols

    if family in ("ruby", "php", "swift"):
        default_vis = "internal" if family == "swift" else "public"
        first_class = None
        for m in _RB_PHP_SWIFT_CLASS_RE.finditer(source):
            name = m.group("name")
            if first_class is None:
                first_class = name
            kind_raw = m.group("kind").lower()
            kind_mapped = "enum" if kind_raw == "enum" else ("interface" if kind_raw in ("interface", "trait", "protocol") else "class")
            line_no = source.count("\n", 0, m.start()) + 1
            c_mods, _ = normalize_modifiers_and_return(m.group("mods") or "")
            vis = resolve_visibility_from_modifiers(c_mods, default_visibility=default_vis)
            symbols[name] = _build_sym(name, name, None, kind_mapped, line_no, vis, c_mods, "", None, f"{kind_raw} {name}")
        for m in _RB_PHP_SWIFT_FUNC_RE.finditer(source):
            name = m.group("name")
            f_mods, _ = normalize_modifiers_and_return(m.group("mods") or "")
            vis = resolve_visibility_from_modifiers(f_mods, default_visibility=default_vis)
            params_raw = " ".join((m.group("params") or "").split())
            ret_raw = " ".join((m.group("ret") or "").split()) or None
            line_no = source.count("\n", 0, m.start()) + 1
            sig = f"def {name}({params_raw})" + (f" -> {ret_raw}" if ret_raw else "")
            symbols[name] = _build_sym(
                name, name.split(".")[-1], first_class, "method" if first_class else "function", line_no, vis, f_mods, params_raw, ret_raw, sig
            )
        return symbols

    return symbols


def _parse_ts_js_symbols(source: str) -> dict[str, tuple[str, int, str, list[str], str | None]]:
    """Extract TypeScript/JavaScript symbols cleanly (backwards-compatible wrapper)."""
    return _parse_multilang_symbols_uncached(source, "module.ts")


def _parse_multilang_symbols_rich(
    source: str,
    file_path: str,
) -> dict[str, ParsedMultiLangSymbol]:
    """Parse structured multi-language symbols using Tree-sitter with fallback parser support."""
    ts_res = parse_multilang_symbols_treesitter(source, file_path)
    if ts_res is not None:
        return ts_res
    return _parse_multilang_symbols_rich_fallback(source, file_path)


def _parse_multilang_symbols(
    source: str,
    file_path: str,
) -> dict[str, tuple[str, int, str, list[str], str | None]]:
    """Cache-aware wrapper around the multi-language symbol parser (cache is opt-in)."""
    cache = get_active_cache()
    if cache is None:
        return _parse_multilang_symbols_uncached(source, file_path)
    key = compute_cache_key("multilang", file_path, source)
    cached = cache.get(key)
    if isinstance(cached, dict):
        try:
            return {
                name: (str(v[0]), int(v[1]), str(v[2]), [str(p) for p in v[3]], None if v[4] is None else str(v[4]))
                for name, v in cached.items()
            }
        except (TypeError, ValueError, IndexError, KeyError):
            pass
    result = _parse_multilang_symbols_uncached(source, file_path)
    cache.put(key, {name: list(v) for name, v in result.items()})
    return result


def _parse_multilang_symbols_uncached(
    source: str,
    file_path: str,
) -> dict[str, tuple[str, int, str, list[str], str | None]]:
    """Extract structural symbols across non-Python languages as compact 5-tuples."""
    rich = _parse_multilang_symbols_rich(source, file_path)
    return {
        qname: (sym.symbol_kind, sym.start_line, sym.signature_str, list(sym.params), sym.return_type)
        for qname, sym in rich.items()
    }


def _extract_brace_or_end_body(source: str, start_idx: int, is_ruby: bool = False) -> str:
    """Extract the body of a function starting near start_idx up to matching '}' or Ruby 'end'."""
    max_window = source[start_idx : start_idx + 12000]
    if is_ruby:
        end_match = re.search(r"^\s*end\b", max_window, re.MULTILINE)
        return max_window[: end_match.start()] if end_match else max_window[:2000]
    brace_pos = max_window.find("{")
    if brace_pos == -1:
        return ""
    semi_pos = max_window.find(";")
    if 0 <= semi_pos < brace_pos:
        return ""
    depth = 0
    for idx in range(brace_pos, len(max_window)):
        ch = max_window[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return max_window[brace_pos + 1 : idx]
    return max_window[brace_pos + 1 : brace_pos + 2500]


def detect_multilang_recursive_functions(
    source: str,
    file_path: str,
) -> dict[str, tuple[bool, list[str]]]:
    """Detect recursive functions and broken recursive self-call arity across non-Python languages (BUG-035).
    Returns dict: symbol_name -> (is_recursive, list_of_arity_mismatch_messages)
    """
    syms = _parse_multilang_symbols(source, file_path)
    if not syms:
        return {}
    lines = source.splitlines(keepends=True)
    line_offsets: list[int] = [0]
    for ln in lines:
        line_offsets.append(line_offsets[-1] + len(ln))

    is_rb = file_path.endswith(".rb")
    results: dict[str, tuple[bool, list[str]]] = {}

    for sym_name, (kind, line_no, _sig, param_items, _ret) in syms.items():
        if kind not in ("function", "method"):
            continue
        short_n = sym_name.split("::")[-1].split(".")[-1]
        if len(short_n) < 2 or short_n in _CPP_CONTROL_KEYWORDS or short_n in _JS_CONTROL_KEYWORDS:
            continue
        start_offset = line_offsets[min(max(0, line_no - 1), len(line_offsets) - 1)]
        first_nl = source.find("\n", start_offset)
        body_search_start = first_nl if first_nl != -1 else start_offset
        body = _extract_brace_or_end_body(source, start_offset, is_ruby=is_rb)
        if not body:
            continue
        # Strip line comments to avoid false-positive self-call matches in comments
        body_clean = re.sub(r"//[^\n]*|#[^\n]*", "", body)
        # Skip the signature line itself if present
        sig_end = body_search_start - start_offset
        if sig_end > 0 and is_rb:
            body_clean = body_clean[min(sig_end, len(body_clean)) :]

        raw_matches = list(re.finditer(rf"\b{re.escape(short_n)}\s*\(", body_clean))
        call_matches = []
        for cm in raw_matches:
            prefix = body_clean[max(0, cm.start() - 32) : cm.start()].rstrip()
            if prefix.endswith((".", "->", "::")):
                if not prefix.endswith(("this.", "this->", "$this->", "self.", "self::", "static::")):
                    continue
            elif any(prefix.endswith(kw) for kw in ("function", "def", "fn", "func")):
                continue
            call_matches.append(cm)
        if not call_matches:
            continue

        min_req = sum(
            1
            for p in param_items
            if "=" not in p and "?" not in p and "..." not in p and not p.startswith("*")
        )
        arity_errors: list[str] = []
        if min_req > 0:
            for cm in call_matches:
                line_start = body_clean.rfind("\n", 0, cm.start()) + 1
                line_end = body_clean.find("\n", cm.end())
                call_line = body_clean[line_start : (line_end if line_end != -1 else len(body_clean))]
                arg_cnt = _count_call_args_in_text(call_line, short_n)
                if arg_cnt is not None and arg_cnt < min_req:
                    arity_errors.append(
                        f"Recursive self-call `{call_line.strip()[:80]}` passes {arg_cnt} argument(s), "
                        f"but `{sym_name}` requires at least {min_req}."
                    )
        results[sym_name] = (True, arity_errors)
    return results


def count_recursive_functions_in_source(source: str, file_path: str) -> int:
    """Count recursive functions in Python or any supported multi-language source file."""
    if file_path.endswith(".py"):
        syms = _parse_python_symbols(source, file_path=file_path)
        return sum(1 for s in syms.values() if s.is_recursive)
    if file_path.endswith(SUPPORTED_NON_PY_CODE_EXTS):
        rec_map = detect_multilang_recursive_functions(source, file_path)
        return sum(1 for is_rec, _ in rec_map.values() if is_rec)
    return 0


def _list_repo_files_at_target(repo_path: Path, target_sha: str) -> list[str]:
    if target_sha == "WORKING_TREE":
        proc = run_git_command(repo_path, ["ls-files"], check=True)
    else:
        proc = run_git_command(repo_path, ["ls-tree", "-r", "--name-only", target_sha], check=True)
    if proc.returncode != 0:
        return []
    return [f.strip().replace("\\", "/") for f in proc.stdout.splitlines() if f.strip()]


def _build_line_to_enclosing_symbol(tree: ast.AST) -> dict[int, str]:
    """Map source line numbers inside a Python AST to their enclosing function or class name."""
    line_map: dict[int, str] = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = getattr(node, "lineno", 1)
            end = getattr(node, "end_lineno", start)
            for ln in range(start, end + 1):
                line_map[ln] = node.name
        elif isinstance(node, ast.ClassDef):
            c_start = getattr(node, "lineno", 1)
            c_end = getattr(node, "end_lineno", c_start)
            for ln in range(c_start, c_end + 1):
                line_map[ln] = node.name
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    m_start = getattr(item, "lineno", 1)
                    m_end = getattr(item, "end_lineno", m_start)
                    for ln in range(m_start, m_end + 1):
                        line_map[ln] = f"{node.name}.{item.name}"
    return line_map


def _detect_py_dynamic_calls(
    tree: ast.AST,
    lines: list[str],
    rel_path: str,
    line_map: dict[int, str],
    breaking_short_names: dict[str, str],
) -> list[UnresolvedDynamicCallItem]:
    """Detect dynamic dispatch, reflection (getattr), globals/locals lookups, and eval/exec in Python AST."""
    dynamic_items: list[UnresolvedDynamicCallItem] = []
    seen_lines: set[int] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lineno = getattr(node, "lineno", 1)
        if lineno in seen_lines:
            continue
        snippet = lines[lineno - 1].strip()[:160] if 1 <= lineno <= len(lines) else ""
        enclosing = line_map.get(lineno)

        # 1. getattr(obj, attr) / hasattr(obj, attr)
        if isinstance(node.func, ast.Name) and node.func.id in ("getattr", "hasattr", "setattr"):
            if len(node.args) >= 2:
                second_arg = node.args[1]
                if isinstance(second_arg, ast.Constant) and isinstance(second_arg.value, str):
                    attr_str = second_arg.value
                    if attr_str in breaking_short_names:
                        seen_lines.add(lineno)
                        dynamic_items.append(
                            UnresolvedDynamicCallItem(
                                file_path=rel_path,
                                line_number=lineno,
                                enclosing_symbol=enclosing,
                                pattern_kind="getattr_reflection",
                                snippet=snippet,
                                referenced_symbol_hint=breaking_short_names[attr_str],
                                risk_explanation=(
                                    f"Reflective `{node.func.id}` lookup explicitly references modified symbol "
                                    f"'{attr_str}' at `{rel_path}:{lineno}`."
                                ),
                            )
                        )
                else:
                    seen_lines.add(lineno)
                    dynamic_items.append(
                        UnresolvedDynamicCallItem(
                            file_path=rel_path,
                            line_number=lineno,
                            enclosing_symbol=enclosing,
                            pattern_kind="getattr_reflection",
                            snippet=snippet,
                            referenced_symbol_hint=None,
                            risk_explanation=(
                                f"Dynamic `{node.func.id}` reflection with non-literal attribute name at "
                                f"`{rel_path}:{lineno}` cannot be statically resolved to a fixed symbol."
                            ),
                        )
                    )

        # 2. eval(...) / exec(...)
        elif isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec", "__import__"):
            seen_lines.add(lineno)
            kind = "importlib_dynamic" if node.func.id == "__import__" else "eval_exec_dynamic"
            dynamic_items.append(
                UnresolvedDynamicCallItem(
                    file_path=rel_path,
                    line_number=lineno,
                    enclosing_symbol=enclosing,
                    pattern_kind=kind,  # type: ignore[arg-type]
                    snippet=snippet,
                    referenced_symbol_hint=None,
                    risk_explanation=(
                        f"Dynamic `{node.func.id}(...)` execution at `{rel_path}:{lineno}` may invoke modified symbols at runtime."
                    ),
                )
            )

        # 3. importlib.import_module(...)
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
        ):
            seen_lines.add(lineno)
            dynamic_items.append(
                UnresolvedDynamicCallItem(
                    file_path=rel_path,
                    line_number=lineno,
                    enclosing_symbol=enclosing,
                    pattern_kind="importlib_dynamic",
                    snippet=snippet,
                    referenced_symbol_hint=None,
                    risk_explanation=(
                        f"Dynamic module import `import_module(...)` at `{rel_path}:{lineno}` may load modified exports at runtime."
                    ),
                )
            )

        # 4. globals() / locals() namespace lookup (e.g. fn = globals()[name] or globals().get(name))
        elif isinstance(node.func, ast.Name) and node.func.id in ("globals", "locals"):
            seen_lines.add(lineno)
            dynamic_items.append(
                UnresolvedDynamicCallItem(
                    file_path=rel_path,
                    line_number=lineno,
                    enclosing_symbol=enclosing,
                    pattern_kind="globals_locals_lookup",
                    snippet=snippet,
                    referenced_symbol_hint=None,
                    risk_explanation=(
                        f"Dynamic `{node.func.id}()` namespace lookup at `{rel_path}:{lineno}` "
                        f"bypasses static call graph resolution."
                    ),
                )
            )

        # 5. globals()[name](...) or locals()[name](...) or obj.__dict__[name](...)
        elif isinstance(node.func, ast.Subscript):
            sub_val_str = _unparse_safe(node.func.value) or ""
            if any(tok in sub_val_str for tok in ("globals()", "locals()", "__dict__", "registry", "handlers", "dispatch")):
                seen_lines.add(lineno)
                hint: str | None = None
                slice_str = _unparse_safe(node.func.slice) or ""
                cleaned_slice = slice_str.strip("'\"")
                if cleaned_slice in breaking_short_names:
                    hint = breaking_short_names[cleaned_slice]
                dynamic_items.append(
                    UnresolvedDynamicCallItem(
                        file_path=rel_path,
                        line_number=lineno,
                        enclosing_symbol=enclosing,
                        pattern_kind="globals_locals_lookup",
                        snippet=snippet,
                        referenced_symbol_hint=hint,
                        risk_explanation=(
                            f"Dynamic dictionary/namespace dispatch `{sub_val_str}[{slice_str}](...)` at "
                            f"`{rel_path}:{lineno}` bypasses static call graph resolution."
                        ),
                    )
                )

    return dynamic_items


_TS_DYNAMIC_DISPATCH_RE = re.compile(
    r"(?:\b(?:eval|Reflect\.apply)\s*\(|[A-Za-z0-9_$)\]]+\[\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*\]\s*\()"
)
_PY_DYN_PRE_RE = re.compile(
    r"getattr|hasattr|setattr|\beval\b|\bexec\b|__import__|import_module|globals|locals|__dict__|registry|handlers|dispatch"
)


def _count_call_args_in_text(line: str, func_name: str) -> int | None:
    """Extract argument count from a text call site `func_name(a, b)` in Markdown or TS."""
    m = re.search(rf"\b{re.escape(func_name)}\s*\(([^)]*)\)", line)
    if not m:
        return None
    inner = m.group(1).strip()
    if not inner:
        return 0
    # Split top-level commas ignoring nested parens/brackets
    depth = 0
    count = 1
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            count += 1
    return count


_COMPILED_LANGUAGE_FAMILIES = frozenset(
    {"go", "rust", "c_cpp", "csharp", "java", "kotlin", "scala", "swift"}
)
_POSITIONAL_ONLY_FAMILIES = frozenset({"go", "c_cpp", "rust", "java", "ts_js"})
_GENERIC_CALLER_NAMES = frozenset(
    {
        "list", "dict", "set", "tuple", "str", "int", "float", "bool", "open",
        "len", "format", "id", "input", "type", "next", "iter", "filter",
        "map", "zip", "print", "sum", "min", "max", "hash", "range", "super",
        "object", "vars", "dir", "compile",
        "main", "run", "start", "stop", "init", "setup", "teardown", "close",
        "read", "write", "get", "set", "put", "post", "delete", "update",
        "create", "remove", "add", "clear", "reset", "check", "parse",
        "parse_args", "build", "load", "save", "dump", "send", "recv",
        "free", "alloc", "malloc", "is_available", "available", "register",
        "eval", "unregister", "handle", "process", "render", "validate", "connect",
        "disconnect", "flush", "sync", "wait", "notify", "emit", "on", "off",
        "clone", "copy", "equals", "toString", "Dispose", "ToString",
        "Equals", "GetHashCode", "hashCode", "__construct", "__destruct",
        "__invoke", "__toString", "__call", "operator()",
    }
)
_GENERIC_RECEIVERS = frozenset(
    {
        "self", "this", "cls", "super", "base", "s", "c", "client", "agent",
        "svc", "service", "instance", "obj", "x", "m", "p", "v", "target",
        "res", "ctx",
    }
)
_OWNER_SUFFIX_RE = re.compile(
    r"(?:Service|Client|Agent|Manager|Handler|Controller|Provider|Impl|Repository|Helper|Factory|Store|Parser)$",
    re.IGNORECASE,
)
_DECL_LINE_RE = re.compile(
    r"^\s*(?:func|fn|def|function|public|protected|private|internal|static|virtual|override|abstract|extern|inline|constexpr|consteval|explicit|friend|sealed|async|suspend|open|class|struct|interface|enum|type)\b"
)
_CPP_LINE_DECL_RE = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_<>*&:\s]+\s+[A-Za-z_][A-Za-z0-9_:*]*\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:final\s*)?(?:\{|$)"
)
_PY_DYN_GREP_REGEX = r"(getattr|hasattr|setattr|eval|exec|__import__|import_module|globals|locals)\("
_TS_DYN_GREP_REGEX = r"(Reflect\.apply|\beval\s*\(|\[[A-Za-z_$][A-Za-z0-9_$.]*\]\s*\()"


def _receiver_matches_owner(receiver: str | None, owner_type: str | None) -> bool:
    """Return False when a specific non-generic call receiver conflicts with owner_type."""
    if not receiver or not owner_type:
        return True
    r_low = receiver.lower().strip()
    if r_low in _GENERIC_RECEIVERS or len(r_low) <= 1:
        return True
    o_low = owner_type.lower().strip()
    if r_low in o_low or o_low in r_low:
        return True
    o_stem = _OWNER_SUFFIX_RE.sub("", o_low).strip()
    if len(o_stem) >= 3 and (o_stem in r_low or r_low in o_stem):
        return True
    return False


def _strip_comments_preserve_newlines(source: str, family: str) -> str:
    """Replace block/line comments with equal newline counts for line-accurate fallback call scans."""
    out = re.sub(
        r"/\*[\s\S]*?\*/",
        lambda m: "\n" * m.group(0).count("\n"),
        source,
    )
    if family == "ruby":
        out = re.sub(r"#[^\n]*", "", out)
    else:
        out = re.sub(r"//[^\n]*", "", out)
        if family in ("php",):
            out = re.sub(r"#[^\n]*", "", out)
    return out


def _extract_multilang_calls_fallback(
    content: str,
    rel_path: str,
    target_short_names: set[str],
    call_regex: re.Pattern[str] | None,
) -> list[ParsedCallSite]:
    """Extract call sites cleanly without Tree-sitter, skipping comments, strings, and declarations."""
    if call_regex is None or not target_short_names:
        return []
    family = get_language_family(rel_path)
    cleaned = _strip_comments_preserve_newlines(content, family)
    raw_lines = content.splitlines()
    clean_lines = cleaned.splitlines()
    calls: list[ParsedCallSite] = []

    for idx, cline in enumerate(clean_lines, start=1):
        stripped = cline.strip()
        if not stripped:
            continue
        if _DECL_LINE_RE.match(stripped):
            continue
        if family == "c_cpp" and _CPP_LINE_DECL_RE.match(stripped) and "=" not in stripped.split("(", 1)[0]:
            continue
        # Blank out quoted literals to ignore symbol names inside string constants
        no_str = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`', '""', cline)
        if not call_regex.search(no_str):
            continue
        raw_snippet = raw_lines[idx - 1].strip()[:160] if idx - 1 < len(raw_lines) else stripped[:160]
        for m in call_regex.finditer(no_str):
            short_n = m.group(1)
            prefix = no_str[: m.start()].rstrip()
            recv: str | None = None
            m_recv = re.search(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:\.|::|->|\\)\s*$", prefix)
            if m_recv:
                recv = m_recv.group(1)
            # Skip unannotated definition headers like `Ret Foo(a, b) {` without `=` or `return` or `await`
            if (
                not recv
                and stripped.endswith("{")
                and "=" not in prefix
                and not prefix.lstrip().startswith(("return", "if", "while", "for", "else", "await"))
                and re.match(r"^[A-Za-z_][A-Za-z0-9_<>*&:\s]+\s+$", prefix)
            ):
                continue
            calls.append(
                ParsedCallSite(
                    callee_name=short_n,
                    receiver=recv,
                    line_number=idx,
                    arg_count=_count_call_args_in_text(no_str, short_n),
                    call_snippet=raw_snippet,
                )
            )
    return calls


def _has_multilang_scope_affinity(content: str, caller_path: str, def_path: str, owner_type: str | None) -> bool:
    """Return True if caller_path belongs to the same package/dir or imports/includes def_path."""
    if caller_path == def_path:
        return True
    caller_dir = Path(caller_path).parent.as_posix()
    def_dir = Path(def_path).parent.as_posix()
    if caller_dir == def_dir:
        return True
    def_stem = Path(def_path).stem
    def_name = Path(def_path).name
    for line in content.splitlines()[:120]:
        s = line.strip()
        if s.startswith(("#include", "import ", "using ", "use ", "require", "from ")) or " from " in s:
            if def_name in s or (len(def_stem) >= 3 and def_stem in s) or (owner_type and len(owner_type) >= 3 and owner_type in s):
                return True
    return False


def _python_import_matches_def(
    file_imports: dict[str, str],
    callee_name: str | None,
    def_file_path: str,
    owner_t: str | None,
) -> bool:
    """Return True when file_imports contains a segment-verified import for def_file_path / owner_t / callee_name."""
    if not file_imports:
        return False
    norm_def = def_file_path.replace("\\", "/")
    if norm_def.endswith(".py"):
        norm_def = norm_def[:-3]
    for prefix in ("src/", "lib/"):
        if norm_def.startswith(prefix):
            norm_def = norm_def[len(prefix) :]
            break
    def_parts = [p for p in norm_def.split("/") if p]
    if def_parts and def_parts[-1] == "__init__":
        def_parts.pop()
    def_stem = def_parts[-1] if def_parts else Path(def_file_path).stem
    def_parent = def_parts[-2] if len(def_parts) >= 2 else None
    pkg_root = def_parts[0] if len(def_parts) >= 2 else None

    def _imp_segs(val: str) -> list[str]:
        return [s for s in val.split(".") if s]

    def _module_matches(segs: list[str]) -> bool:
        if not def_stem or def_stem not in segs:
            return False
        idx = segs.index(def_stem)
        if def_parent and idx > 0 and segs[idx - 1] != def_parent:
            return False
        return True

    if callee_name and callee_name in file_imports:
        c_segs = _imp_segs(file_imports[callee_name])
        if _module_matches(c_segs) or (pkg_root and c_segs and c_segs[0] == pkg_root and callee_name in c_segs):
            return True

    if owner_t and owner_t in file_imports:
        o_segs = _imp_segs(file_imports[owner_t])
        if _module_matches(o_segs) or (pkg_root and o_segs and o_segs[0] == pkg_root and owner_t in o_segs):
            return True

    for imp_val in file_imports.values():
        if _module_matches(_imp_segs(imp_val)):
            return True
    return False


def _scan_callers_and_tests_and_docs(
    extraction: RawRangeExtraction,
    symbol_changes: list[SymbolSignatureChange],
    modified_symbol_names: set[str],
    new_py_symbols_by_qname: dict[str, _PySymbolInfo] | None = None,
    symbol_owners: dict[tuple[str, str], str] | None = None,
    symbol_arity_bounds: dict[tuple[str, str], tuple[int, int, bool]] | None = None,
) -> tuple[
    dict[tuple[str, str], list[CallerImpactItem]],
    dict[tuple[str, str], int],
    list[str],
    list[DocDriftItem],
    list[UnresolvedDynamicCallItem],
    AnalysisCoverageReport,
]:
    """Scan repository files for call sites of breaking symbols, arity mismatches, dynamic calls, test coverage, and doc drift."""
    repo_path = extraction.repo_path
    target_sha = extraction.resolved_target_sha
    all_files = _list_repo_files_at_target(repo_path, target_sha)
    new_py_map = new_py_symbols_by_qname or {}
    owner_lookup = symbol_owners or {}
    arity_lookup = symbol_arity_bounds or {}

    breaking_short_names: dict[str, str] = {}
    breaking_keys_by_short: dict[str, list[tuple[str, str]]] = {}
    breaking_by_key: dict[tuple[str, str], SymbolSignatureChange] = {}
    sev_rank = {"high": 3, "medium": 2, "low": 1}
    for sc in symbol_changes:
        if sc.is_breaking_candidate:
            base_sym = sc.symbol_name.split("#", 1)[0]
            short = base_sym.split("::")[-1].split(".")[-1]
            key = short if short not in ("__init__", "__call__") else base_sym.split(".")[0]
            comp_key = (sc.file_path, sc.symbol_name)
            breaking_short_names[key] = sc.symbol_name
            klist = breaking_keys_by_short.setdefault(key, [])
            if comp_key not in klist:
                klist.append(comp_key)
            existing = breaking_by_key.get(comp_key)
            if existing is None or sev_rank.get(sc.severity, 0) > sev_rank.get(existing.severity, 0):
                breaking_by_key[comp_key] = sc

    caller_impacts: dict[tuple[str, str], list[CallerImpactItem]] = {
        comp_key: [] for comp_key in breaking_by_key
    }
    caller_totals: dict[tuple[str, str], int] = {comp_key: 0 for comp_key in breaking_by_key}
    tested_symbols: set[str] = set()
    doc_drift_items: list[DocDriftItem] = []
    unresolved_dynamic_calls: list[UnresolvedDynamicCallItem] = []

    changed_doc_paths = {f.file_path for f in extraction.changed_files if f.is_doc_file}

    total_code_eligible = 0
    files_parsed_ok = 0
    files_skipped_or_err = 0

    eligible_code_files = [
        f for f in all_files if f.endswith(SUPPORTED_ALL_CODE_EXTS) and not _is_lockfile_or_generated(f)
    ]
    eligible_doc_files = [
        f for f in all_files if f.endswith((".md", ".rst")) and not _is_lockfile_or_generated(f)
    ]

    # Pre-compile combined regexes once outside the file loop to avoid O(files * symbols * lines) blowup (BUG-033)
    mod_short_to_qnames: dict[str, list[str]] = {}
    for sym_qname in modified_symbol_names:
        base_q = sym_qname.split("#", 1)[0]
        short_n = base_q.split("::")[-1].split(".")[-1]
        if short_n in ("__init__", "__call__"):
            short_n = base_q.split(".")[0]
        if short_n:
            mod_short_to_qnames.setdefault(short_n, []).append(sym_qname)

    _mod_test_re = (
        re.compile(rf"\b({'|'.join(re.escape(k) for k in mod_short_to_qnames)})\b")
        if mod_short_to_qnames
        else None
    )
    _breaking_call_re = (
        re.compile(rf"\b({'|'.join(re.escape(k) for k in breaking_keys_by_short)})\s*\(")
        if breaking_keys_by_short
        else None
    )
    _breaking_ident_re = (
        re.compile(rf"\b({'|'.join(re.escape(k) for k in breaking_keys_by_short)})\b")
        if breaking_keys_by_short
        else None
    )
    _doc_call_res = {
        k: re.compile(rf"\b{re.escape(k)}\s*\(")
        for k in breaking_keys_by_short
    }

    full_repo_prefilter_used = False
    files_omitted_count = 0
    truncated = False
    verified_clean_code = 0

    all_eligible = eligible_code_files + eligible_doc_files
    if len(eligible_code_files) > 400:
        search_terms = sorted(set(mod_short_to_qnames.keys()) | set(breaking_keys_by_short.keys()))
        dyn_regexes = [_PY_DYN_GREP_REGEX, _TS_DYN_GREP_REGEX] if (symbol_changes or modified_symbol_names) else []
        prefilter_matches = git_grep_matching_files(
            repo_path,
            target_sha,
            search_terms,
            regex_patterns=dyn_regexes,
        )
        if prefilter_matches is not None:
            full_repo_prefilter_used = True
            changed_paths = {f.file_path for f in extraction.changed_files}
            candidate_set = prefilter_matches | changed_paths
            candidate_code = [f for f in eligible_code_files if f in candidate_set]
            candidate_docs = [f for f in eligible_doc_files if f in candidate_set]
            verified_clean_code = len(eligible_code_files) - len(candidate_code)
            scan_pool = candidate_code + candidate_docs
            max_candidates = 4000
            if len(scan_pool) > max_candidates:
                files_omitted_count = sum(
                    1 for f in scan_pool[max_candidates:] if f.endswith(SUPPORTED_ALL_CODE_EXTS)
                )
                truncated = True
                scan_paths = scan_pool[:max_candidates]
            else:
                scan_paths = scan_pool
        else:
            max_fallback = 2500
            if len(all_eligible) > max_fallback:
                files_omitted_count = sum(
                    1 for f in all_eligible[max_fallback:] if f.endswith(SUPPORTED_ALL_CODE_EXTS)
                )
                truncated = True
                scan_paths = all_eligible[:max_fallback]
            else:
                scan_paths = all_eligible
    else:
        max_small = 4000
        if len(all_eligible) > max_small:
            files_omitted_count = sum(
                1 for f in all_eligible[max_small:] if f.endswith(SUPPORTED_ALL_CODE_EXTS)
            )
            truncated = True
            scan_paths = all_eligible[:max_small]
        else:
            scan_paths = all_eligible

    batch_target_blobs: dict[str, str] = {}
    if target_sha != "WORKING_TREE":
        missing_paths = [p for p in scan_paths if p not in extraction.target_blobs]
        if missing_paths:
            batch_target_blobs = read_blobs_at_revision(
                repo_path,
                target_sha,
                missing_paths,
                max_bytes=256 * 1024,
            )

    breaking_short_set = set(breaking_keys_by_short.keys())

    def _resolve_owner(sc_item: SymbolSignatureChange) -> str | None:
        explicit = owner_lookup.get((sc_item.file_path, sc_item.symbol_name))
        if explicit:
            return explicit
        if "::" in sc_item.symbol_name:
            return sc_item.symbol_name.rsplit("::", 1)[0].split("::")[-1]
        if "." in sc_item.symbol_name:
            return sc_item.symbol_name.split(".", 1)[0]
        return None

    for rel_path in scan_paths:
        is_py = rel_path.endswith(".py")
        is_ts = rel_path.endswith(SUPPORTED_NON_PY_CODE_EXTS)
        is_md = rel_path.endswith((".md", ".rst"))

        if is_py or is_ts:
            total_code_eligible += 1

        content = extraction.target_blobs.get(rel_path)
        if content is None:
            if target_sha == "WORKING_TREE":
                candidate = repo_path / rel_path
                if candidate.exists() and candidate.is_file() and is_safe_repo_file(repo_path, candidate):
                    try:
                        if candidate.stat().st_size <= 256 * 1024:
                            content = decode_bytes_safely(candidate.read_bytes())
                    except OSError:
                        content = None
            else:
                content = batch_target_blobs.get(rel_path)

        if content is None:
            if is_py or is_ts:
                files_skipped_or_err += 1
            continue

        is_test = _is_test_file(rel_path)
        if is_test and _mod_test_re is not None:
            for m_test in _mod_test_re.finditer(content):
                for qn in mod_short_to_qnames.get(m_test.group(1), ()):
                    tested_symbols.add(qn)

        if is_py:
            try:
                tree = _parse_py_ast_quietly(content)
                files_parsed_ok += 1
                lines = content.splitlines()
                line_map = _build_line_to_enclosing_symbol(tree)

                if not is_test and len(unresolved_dynamic_calls) < 25 and _PY_DYN_PRE_RE.search(content):
                    dyn_found = _detect_py_dynamic_calls(
                        tree, lines, rel_path, line_map, breaking_short_names
                    )
                    unresolved_dynamic_calls.extend(dyn_found[: 25 - len(unresolved_dynamic_calls)])

                if _breaking_ident_re is not None and _breaking_ident_re.search(content):
                    file_imports = _extract_py_imports(tree)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            callee_name: str | None = None
                            is_attr_call = False
                            attr_receiver: str | None = None
                            if isinstance(node.func, ast.Name):
                                callee_name = node.func.id
                            elif isinstance(node.func, ast.Attribute):
                                callee_name = node.func.attr
                                is_attr_call = True
                                if isinstance(node.func.value, ast.Name):
                                    attr_receiver = node.func.value.id
                                elif isinstance(node.func.value, ast.Attribute):
                                    attr_receiver = node.func.value.attr
                            target_short_name: str | None = None
                            if callee_name and callee_name in breaking_keys_by_short:
                                target_short_name = callee_name
                            elif callee_name and callee_name in file_imports:
                                imported_target = file_imports[callee_name].split(".")[-1]
                                if imported_target in breaking_keys_by_short:
                                    target_short_name = imported_target

                            if target_short_name:
                                candidate_keys = breaking_keys_by_short[target_short_name]
                                lineno = getattr(node, "lineno", 1)
                                enclosing = line_map.get(lineno)

                                matched_keys = candidate_keys
                                if len(candidate_keys) > 1 and enclosing and "." in enclosing:
                                    enc_cls = enclosing.split(".")[0]
                                    if attr_receiver in ("self", "cls", enc_cls):
                                        cls_specific = [ck for ck in candidate_keys if ck[1].startswith(f"{enc_cls}.")]
                                        if cls_specific:
                                            matched_keys = cls_specific

                                for comp_key in matched_keys:
                                    _, qname = comp_key
                                    sc_obj = breaking_by_key[comp_key]
                                    # Enforce same language family
                                    if get_language_family(sc_obj.file_path) not in ("", "python"):
                                        continue

                                    def_mod_stem = Path(sc_obj.file_path).stem
                                    owner_t = _resolve_owner(sc_obj)

                                    # Reject bare calls like `copy(x)` against class methods like `OpenAI.copy`
                                    if (
                                        not is_attr_call
                                        and owner_t is not None
                                        and sc_obj.symbol_kind != "class"
                                        and target_short_name != owner_t
                                        and not qname.endswith(".__init__")
                                    ):
                                        continue

                                    # Reject method calls like `provider.list_models()` against top-level functions
                                    if (
                                        is_attr_call
                                        and owner_t is None
                                        and sc_obj.symbol_kind in ("function", "async_function")
                                        and attr_receiver
                                        and attr_receiver != def_mod_stem
                                        and attr_receiver not in file_imports
                                    ):
                                        continue

                                    has_explicit_import = _python_import_matches_def(
                                        file_imports, callee_name, sc_obj.file_path, owner_t
                                    )

                                    is_self_cls_same_class = (
                                        rel_path == sc_obj.file_path
                                        and enclosing is not None
                                        and "." in enclosing
                                        and owner_t == enclosing.split(".")[0]
                                    )
                                    if is_attr_call and attr_receiver and owner_t and not _receiver_matches_owner(attr_receiver, owner_t):
                                        continue

                                    # Guard generic/builtin names (`list`, `main`, `run`, etc.) against bogus cross-file matches
                                    short_key = target_short_name
                                    if short_key in _GENERIC_CALLER_NAMES and not (
                                        rel_path == sc_obj.file_path
                                        or has_explicit_import
                                        or is_self_cls_same_class
                                    ):
                                        continue

                                    if rel_path == sc_obj.file_path or has_explicit_import:
                                        conf_level = "exact_ast"
                                    else:
                                        conf_level = "heuristic_name_match"

                                    snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else (callee_name or target_short_name)
                                    arity_broken, mismatch_msg = _check_call_arity_mismatch(
                                        node,
                                        new_py_map.get(qname),
                                        sc_obj.change_kind,
                                    )
                                    caller_totals[comp_key] = caller_totals.get(comp_key, 0) + 1
                                    if len(caller_impacts.get(comp_key, [])) < 25:
                                        caller_impacts.setdefault(comp_key, []).append(
                                            CallerImpactItem(
                                                caller_file=rel_path,
                                                caller_symbol=callee_name or target_short_name,
                                                enclosing_symbol=enclosing,
                                                line_number=lineno,
                                                call_snippet=snippet[:160],
                                                resolution_confidence=conf_level,
                                                arity_mismatch_detected=arity_broken,
                                                mismatch_details=mismatch_msg,
                                            )
                                        )
            except (SyntaxError, RecursionError, MemoryError):
                files_skipped_or_err += 1

        elif is_ts:
            files_parsed_ok += 1
            lines = content.splitlines()
            caller_family = get_language_family(rel_path)

            if not is_test and len(unresolved_dynamic_calls) < 25:
                for idx, line in enumerate(lines, start=1):
                    if _TS_DYNAMIC_DISPATCH_RE.search(line):
                        unresolved_dynamic_calls.append(
                            UnresolvedDynamicCallItem(
                                file_path=rel_path,
                                line_number=idx,
                                enclosing_symbol=None,
                                pattern_kind="ts_bracket_dispatch",
                                snippet=line.strip()[:160],
                                referenced_symbol_hint=None,
                                risk_explanation=(
                                    f"Dynamic property/reflection invocation in TypeScript/JS at `{rel_path}:{idx}` "
                                    "cannot be statically bound to a fixed export."
                                ),
                            )
                        )
                        if len(unresolved_dynamic_calls) >= 25:
                            break

            if breaking_short_set and _breaking_call_re is not None and _breaking_call_re.search(content):
                ts_calls = extract_multilang_calls_treesitter(content, rel_path, breaking_short_set)
                used_ts_calls = ts_calls is not None
                call_sites = (
                    ts_calls
                    if ts_calls is not None
                    else _extract_multilang_calls_fallback(content, rel_path, breaking_short_set, _breaking_call_re)
                )

                for csite in call_sites:
                    short_n = csite.callee_name
                    for comp_key in breaking_keys_by_short.get(short_n, ()):
                        _, qname = comp_key
                        sc_obj = breaking_by_key[comp_key]
                        def_family = get_language_family(sc_obj.file_path)
                        if def_family and caller_family and def_family != caller_family:
                            continue
                        # Never count the symbol's own declaration line as a caller
                        if (
                            rel_path == sc_obj.file_path
                            and sc_obj.target_line_span
                            and sc_obj.target_line_span.start_line == csite.line_number
                        ):
                            continue
                        owner_t = _resolve_owner(sc_obj)
                        if not _receiver_matches_owner(csite.receiver, owner_t):
                            continue
                        if "#" in sc_obj.symbol_name and csite.arg_count is not None:
                            bounds = arity_lookup.get(comp_key)
                            if bounds is not None:
                                min_req, max_params, is_variadic = bounds
                                if not is_variadic and not (min_req <= csite.arg_count <= max_params):
                                    continue
                        has_scope = _has_multilang_scope_affinity(content, rel_path, sc_obj.file_path, owner_t)
                        if short_n in _GENERIC_CALLER_NAMES and not (
                            rel_path == sc_obj.file_path
                            or has_scope
                            or (csite.receiver and owner_t and csite.receiver.lower() in owner_t.lower())
                        ):
                            continue

                        conf = (
                            "exact_ast" if (used_ts_calls and (rel_path == sc_obj.file_path or has_scope)) else "heuristic_name_match"
                        )
                        caller_totals[comp_key] = caller_totals.get(comp_key, 0) + 1
                        if len(caller_impacts.get(comp_key, [])) < 25:
                            caller_impacts.setdefault(comp_key, []).append(
                                CallerImpactItem(
                                    caller_file=rel_path,
                                    caller_symbol=short_n,
                                    line_number=csite.line_number,
                                    call_snippet=csite.call_snippet,
                                    resolution_confidence=conf,
                                )
                            )

        elif is_md and breaking_keys_by_short:
            lines = None
            for short_n, comp_keys in breaking_keys_by_short.items():
                if short_n not in content:
                    continue
                if lines is None:
                    lines = content.splitlines()
                call_pat = _doc_call_res[short_n]
                for comp_key in comp_keys:
                    _, qname = comp_key
                    sc_obj = breaking_by_key[comp_key]
                    target_py_sym = new_py_map.get(qname)
                    min_req_args = (
                        sum(
                            1
                            for p in target_py_sym.params
                            if not p.has_default and p.kind not in ("VAR_POSITIONAL", "VAR_KEYWORD")
                        )
                        if target_py_sym
                        else None
                    )
                    for idx, line in enumerate(lines, start=1):
                        if short_n not in line:
                            continue
                        has_call = bool(call_pat.search(line))
                        has_backtick = f"`{short_n}`" in line or f"`{qname}`" in line
                        if not (has_call or has_backtick):
                            continue

                        call_arg_cnt = _count_call_args_in_text(line, short_n) if has_call else None
                        arity_stale = (
                            call_arg_cnt is not None
                            and min_req_args is not None
                            and call_arg_cnt < min_req_args
                        )

                        if sc_obj.change_kind == "removed" or arity_stale or (rel_path not in changed_doc_paths):
                            ev_id = sc_obj.evidence_ids[0] if sc_obj.evidence_ids else None
                            arity_note = (
                                f" Example passes {call_arg_cnt} argument(s), but updated signature requires at least {min_req_args}."
                                if arity_stale
                                else ""
                            )
                            doc_drift_items.append(
                                DocDriftItem(
                                    doc_file=rel_path,
                                    line_number=idx,
                                    referenced_symbol=qname,
                                    snippet=line.strip()[:160],
                                    drift_reason=(
                                        f"Documentation in '{rel_path}:{idx}' references '{short_n}', "
                                        f"whose signature/availability changed ({sc_obj.change_kind}: {sc_obj.details}).{arity_note}"
                                    ),
                                    evidence_ids=[ev_id] if ev_id else [],
                                )
                            )
                            break

    total_code_eligible += verified_clean_code + files_omitted_count
    files_parsed_ok += verified_clean_code
    files_skipped_or_err += files_omitted_count

    coverage_pct = (
        round((files_parsed_ok / total_code_eligible) * 100.0, 1)
        if total_code_eligible > 0
        else 100.0
    )

    all_caller_items = [c for clist in caller_impacts.values() for c in clist]
    exact_cnt = sum(1 for c in all_caller_items if c.resolution_confidence == "exact_ast")
    heur_cnt = sum(1 for c in all_caller_items if c.resolution_confidence == "heuristic_name_match")
    arity_cnt = sum(1 for c in all_caller_items if c.arity_mismatch_detected)
    dyn_cnt = len(unresolved_dynamic_calls)
    pub_brk_cnt = sum(
        1 for sc in symbol_changes if sc.is_breaking_candidate and sc.is_public_api_export
    )

    reasons: list[str] = []
    conf_rating: ConfidenceLevel = "high"
    if coverage_pct < 75.0 or truncated:
        conf_rating = "low"
        reasons.append(
            f"Parsed {coverage_pct}% ({files_parsed_ok}/{total_code_eligible}) of eligible code files"
            + (f" ({files_omitted_count} files omitted by scan cap)." if files_omitted_count else ".")
        )
    else:
        reasons.append(
            f"Statically verified {coverage_pct}% ({files_parsed_ok}/{total_code_eligible}) of eligible repository source files"
            + (" via full-repo prefilter + AST scan." if full_repo_prefilter_used else ".")
        )

    if dyn_cnt > 0:
        if conf_rating == "high":
            conf_rating = "medium"
        reasons.append(
            f"Detected {dyn_cnt} unresolved dynamic/reflective invocation(s) (e.g., getattr/eval/dynamic dispatch) that sit outside static call graphs."
        )
    if heur_cnt > 0:
        if conf_rating == "high":
            conf_rating = "medium"
        reasons.append(
            f"{heur_cnt} caller reference(s) rely on heuristic name matching rather than proven import bindings."
        )
    if pub_brk_cnt > 0:
        if conf_rating == "high":
            conf_rating = "medium"
        reasons.append(
            f"{pub_brk_cnt} breaking symbol(s) are publicly exported APIs; external downstream consumers outside this repository may be impacted even if internal callers are clean."
        )
    if conf_rating == "high":
        reasons.append("Zero unresolved dynamic calls and zero unverified external public API breakages detected.")

    ts_status = get_treesitter_status()
    parser_backend_label = (
        "python_ast+tree_sitter" if ts_status.get("available") else "python_ast+structural_fallback"
    )

    coverage_report = AnalysisCoverageReport(
        total_repo_files_discovered=len(all_files),
        total_code_files_eligible=total_code_eligible,
        files_parsed_successfully=files_parsed_ok,
        files_skipped_or_unparseable=files_skipped_or_err,
        static_parse_coverage_pct=coverage_pct,
        exact_ast_callers_count=exact_cnt,
        heuristic_callers_count=heur_cnt,
        callers_with_arity_mismatch_count=arity_cnt,
        unresolved_dynamic_calls_count=dyn_cnt,
        public_api_exports_modified_count=pub_brk_cnt,
        parser_backend=parser_backend_label,
        files_omitted_count=files_omitted_count,
        truncated=truncated,
        full_repo_prefilter_used=full_repo_prefilter_used,
        overall_blast_radius_confidence=conf_rating,
        confidence_rationale=" ".join(reasons),
    )

    untested = sorted(modified_symbol_names - tested_symbols)
    return caller_impacts, caller_totals, untested, doc_drift_items, unresolved_dynamic_calls, coverage_report


def _collect_init_reexports(extraction: RawRangeExtraction) -> set[str]:
    """Scan any `__init__.py` blobs in base/target or repo root for re-exported symbol names."""
    reexported: set[str] = set()
    for path_key, blob in {**extraction.base_blobs, **extraction.target_blobs}.items():
        if path_key.endswith("__init__.py") and blob:
            try:
                tree = _parse_py_ast_quietly(blob)
                dunder = _extract_dunder_all(tree)
                if dunder:
                    reexported.update(dunder)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        for alias in node.names:
                            reexported.add(alias.asname or alias.name)
            except (SyntaxError, RecursionError, MemoryError):
                pass
    return reexported


_UNIT_SENSITIVE_KEYWORDS = (
    "timeout",
    "delay",
    "ttl",
    "interval",
    "duration",
    "wait",
    "latency",
    "expiry",
    "expire",
)
_UNIT_SCALE_MARKERS = ("1000", "1e3", "60", "sleep", "millisecond", "second", "_ms", "_s")


def _detect_unit_shift_risk(fpath: str, old_s: _PySymbolInfo, new_s: _PySymbolInfo) -> tuple[str, bool, str, str] | None:
    """Detect possible unit-scaling shifts (e.g. ms vs s) when parameter type stays compatible."""
    haystack = f"{old_s.qualified_name} {old_s.signature_str}".lower()
    if not any(kw in haystack for kw in _UNIT_SENSITIVE_KEYWORDS):
        return None
    old_dump = old_s.body_ast_dump.lower()
    new_dump = new_s.body_ast_dump.lower()
    if old_dump == new_dump:
        return None
    old_hits = {m for m in _UNIT_SCALE_MARKERS if m in old_dump}
    new_hits = {m for m in _UNIT_SCALE_MARKERS if m in new_dump}
    if old_hits != new_hits:
        return (
            "behavior_changed",
            True,
            "medium",
            f"Possible unit-shift in `{new_s.qualified_name}` ({fpath}): parameter type appears unchanged, "
            "but body scaling/unit markers changed. Review callers passing numeric literals or unit-named constants.",
        )
    return None


def _build_added_symbol_recursion_issues(fpath: str, new_s: _PySymbolInfo) -> list[tuple[str, bool, str, str]]:
    """Return high-severity behavioral/signature findings if a newly added function contains recursion defects."""
    issues: list[tuple[str, bool, str, str]] = []
    if new_s.recursive_arity_mismatches:
        issues.append(
            (
                "signature_changed",
                True,
                "high",
                f"Broken recursive self-call in `{new_s.qualified_name}` ({fpath}): "
                + "; ".join(new_s.recursive_arity_mismatches),
            )
        )
    if new_s.has_unconditional_recursion:
        issues.append(
            (
                "behavior_changed",
                True,
                "high",
                f"Unconditional infinite recursion in `{new_s.qualified_name}` ({fpath}): "
                "recursive function invokes itself without any conditional base-case branch or termination guard, guaranteeing `RecursionError` at runtime.",
            )
        )
    if new_s.unqualified_method_self_calls:
        issues.append(
            (
                "behavior_changed",
                True,
                "high",
                f"Broken method self-recursion in `{new_s.qualified_name}` ({fpath}): "
                + "; ".join(new_s.unqualified_method_self_calls),
            )
        )
    return issues


def run_structural_code_analysis(extraction: RawRangeExtraction) -> StructuralAnalysisResult:
    """Run deterministic Python AST and TS/JS signature diffing, caller blast-radius scan, dynamic call scan, and doc-drift detection."""
    symbol_changes: list[SymbolSignatureChange] = []
    modified_symbol_names: set[str] = set()
    new_py_symbols_by_qname: dict[str, _PySymbolInfo] = {}
    init_reexports = _collect_init_reexports(extraction)

    next_ev_num = len(extraction.evidence_registry) + 1
    commit_by_file: dict[str, tuple[str, str]] = {}
    for c in extraction.commits:
        for cf in c.changed_files:
            norm_cf = cf.replace("\\", "/")
            if norm_cf not in commit_by_file:
                commit_by_file[norm_cf] = (c.commit_hash, c.subject)

    def _register_symbol_evidence(
        file_delta_path: str,
        base_span: LineSpan | None,
        target_span: LineSpan | None,
        excerpt: str,
        reason: str,
    ) -> str:
        nonlocal next_ev_num
        eid = f"ev_{next_ev_num:03d}"
        next_ev_num += 1
        norm_delta = file_delta_path.replace("\\", "/")
        default_hash = (
            extraction.commits[0].commit_hash
            if extraction.resolved_target_sha == "WORKING_TREE" and extraction.commits
            else extraction.resolved_target_sha
        )
        default_msg = (
            extraction.commits[0].subject
            if extraction.resolved_target_sha == "WORKING_TREE" and extraction.commits
            else "Working tree or revision diff"
        )
        c_hash, c_msg = commit_by_file.get(norm_delta, (default_hash, default_msg))
        extraction.evidence_registry[eid] = EvidenceRecord(
            evidence_id=eid,
            commit_hash=c_hash,
            commit_message=c_msg,
            file_path=file_delta_path,
            base_line_span=base_span,
            target_line_span=target_span,
            diff_hunk_header=f"AST Symbol Diff ({file_delta_path})",
            diff_excerpt=excerpt[:600],
            reason_supports_finding=reason,
            confidence="high",
        )
        return eid

_VIS_RANK = {"private": 0, "internal": 1, "protected": 2, "public": 3}


def _semantic_compare_multilang_symbol(
    family: str,
    old_sym: ParsedMultiLangSymbol,
    new_sym: ParsedMultiLangSymbol,
    old_rec_errors: list[str],
    rec_errors: list[str],
) -> tuple[bool, bool, str, str] | None:
    """Compare two multi-language declarations semantically.

    Returns ``(has_meaningful_delta, is_breaking_candidate, severity, note_suffix)``
    or ``None`` when changes are purely cosmetic (whitespace, modifier reordering,
    or parameter-name-only renames in positional languages).
    """
    newly_introduced_rec_error = bool(rec_errors and not old_rec_errors)
    vis_narrowed = _VIS_RANK.get(new_sym.visibility, 1) < _VIS_RANK.get(old_sym.visibility, 1)
    vis_widened = _VIS_RANK.get(new_sym.visibility, 1) > _VIS_RANK.get(old_sym.visibility, 1)
    async_changed = ("async" in old_sym.modifiers) != ("async" in new_sym.modifiers)
    static_changed = ("static" in old_sym.modifiers) != ("static" in new_sym.modifiers)

    old_ret_norm = normalize_type_expr(old_sym.return_type or "")
    new_ret_norm = normalize_type_expr(new_sym.return_type or "")
    ret_changed = old_sym.return_type is not None and old_ret_norm != new_ret_norm

    same_param_count = len(old_sym.params) == len(new_sym.params)
    same_req_count = old_sym.required_param_count == new_sym.required_param_count
    same_param_types = old_sym.normalized_param_types == new_sym.normalized_param_types

    is_positional_rename_only = (
        family in _POSITIONAL_ONLY_FAMILIES
        and same_param_count
        and same_req_count
        and same_param_types
    )
    param_types_incompatible = False if family == "ruby" else (not same_param_types)
    if (
        param_types_incompatible
        and len(new_sym.params) > len(old_sym.params)
        and new_sym.required_param_count <= old_sym.required_param_count
    ):
        if (
            new_sym.normalized_param_types[: len(old_sym.normalized_param_types)]
            == old_sym.normalized_param_types
        ):
            param_types_incompatible = False

    param_breaking = (
        new_sym.required_param_count > old_sym.required_param_count
        or len(new_sym.params) < len(old_sym.params)
        or (not is_positional_rename_only and param_types_incompatible)
    )
    param_optional_added = len(new_sym.params) > len(old_sym.params) and not param_breaking

    has_meaningful_delta = (
        newly_introduced_rec_error
        or vis_narrowed
        or vis_widened
        or async_changed
        or static_changed
        or ret_changed
        or param_breaking
        or param_optional_added
    )
    if not has_meaningful_delta:
        return None

    is_brk = (
        bool(rec_errors)
        or vis_narrowed
        or async_changed
        or static_changed
        or ret_changed
        or param_breaking
    )
    notes: list[str] = []
    if vis_narrowed:
        notes.append(f"Visibility narrowed ({old_sym.visibility} -> {new_sym.visibility}).")
    if rec_errors:
        notes.append(f"Recursive self-call bug: {rec_errors[0]}")
    sev = "high" if is_brk else "low"
    return True, is_brk, sev, (" " + " ".join(notes)) if notes else ""


def _is_ml_variadic(sym: ParsedMultiLangSymbol) -> bool:
    """Return True if a multi-language symbol accepts variadic arguments."""
    return any(
        "..." in p or p.lstrip().startswith("*") or "params " in p or "vararg " in p
        for p in sym.params
    )


def _pair_multilang_overloads(
    lang_family: str,
    old_ts: dict[str, ParsedMultiLangSymbol],
    new_ts: dict[str, ParsedMultiLangSymbol],
) -> tuple[
    list[tuple[str, ParsedMultiLangSymbol, ParsedMultiLangSymbol]],
    list[tuple[str, ParsedMultiLangSymbol]],
    list[tuple[str, ParsedMultiLangSymbol]],
]:
    """Match multi-language overloads order-independently across old/new versions."""
    old_groups: dict[str, list[tuple[str, ParsedMultiLangSymbol]]] = {}
    for k, s in old_ts.items():
        old_groups.setdefault(k.split("#", 1)[0], []).append((k, s))

    new_groups: dict[str, list[tuple[str, ParsedMultiLangSymbol]]] = {}
    for k, s in new_ts.items():
        new_groups.setdefault(k.split("#", 1)[0], []).append((k, s))

    paired: list[tuple[str, ParsedMultiLangSymbol, ParsedMultiLangSymbol]] = []
    removed: list[tuple[str, ParsedMultiLangSymbol]] = []
    added: list[tuple[str, ParsedMultiLangSymbol]] = []

    for base in sorted(set(old_groups) | set(new_groups)):
        og = old_groups.get(base, [])
        ng = new_groups.get(base, [])
        if not ng:
            removed.extend(og)
            continue
        if not og:
            added.extend(ng)
            continue
        if len(og) == 1 and len(ng) == 1:
            paired.append((ng[0][0], og[0][1], ng[0][1]))
            continue

        used_old: set[int] = set()
        used_new: set[int] = set()

        def _is_exact(o_sym: ParsedMultiLangSymbol, n_sym: ParsedMultiLangSymbol) -> bool:
            if o_sym.symbol_kind != n_sym.symbol_kind:
                return False
            if (
                o_sym.normalized_param_types == n_sym.normalized_param_types
                and o_sym.return_type == n_sym.return_type
                and o_sym.visibility == n_sym.visibility
                and o_sym.required_param_count == n_sym.required_param_count
            ):
                return True
            return _semantic_compare_multilang_symbol(lang_family, o_sym, n_sym, [], []) is None

        # Pass 1a: exact matches preserving identical dictionary keys first
        for oi, (ok, osym) in enumerate(og):
            for ni, (nk, nsym) in enumerate(ng):
                if ni in used_new or ok != nk:
                    continue
                if _is_exact(osym, nsym):
                    used_old.add(oi)
                    used_new.add(ni)
                    paired.append((nk, osym, nsym))
                    break

        # Pass 1b: exact matches across shifted `#N` overload positions
        for oi, (_ok, osym) in enumerate(og):
            if oi in used_old:
                continue
            for ni, (nk, nsym) in enumerate(ng):
                if ni in used_new:
                    continue
                if _is_exact(osym, nsym):
                    used_old.add(oi)
                    used_new.add(ni)
                    paired.append((nk, osym, nsym))
                    break

        # Pass 2: greedy similarity matching for modified overloads of same symbol_kind
        rem_old_indices = [oi for oi in range(len(og)) if oi not in used_old]
        rem_new_indices = [ni for ni in range(len(ng)) if ni not in used_new]
        if rem_old_indices and rem_new_indices:
            single_rem = len(rem_old_indices) == 1 and len(rem_new_indices) == 1
            scored: list[tuple[int, int, int]] = []
            for oi in rem_old_indices:
                osym = og[oi][1]
                for ni in rem_new_indices:
                    nsym = ng[ni][1]
                    if osym.symbol_kind != nsym.symbol_kind:
                        continue
                    shared_prefix = 0
                    for a, b in zip(osym.normalized_param_types, nsym.normalized_param_types):
                        if a == b:
                            shared_prefix += 1
                        else:
                            break
                    shared_total = sum(
                        1 for a, b in zip(osym.normalized_param_types, nsym.normalized_param_types) if a == b
                    )
                    if not (len(osym.params) == len(nsym.params) or shared_prefix > 0 or single_rem):
                        continue
                    score = (
                        10 if len(osym.params) == len(nsym.params) else -abs(len(osym.params) - len(nsym.params))
                    ) + 2 * shared_total
                    scored.append((score, oi, ni))
            scored.sort(key=lambda item: (-item[0], item[1], item[2]))
            for _score, oi, ni in scored:
                if oi in used_old or ni in used_new:
                    continue
                used_old.add(oi)
                used_new.add(ni)
                paired.append((ng[ni][0], og[oi][1], ng[ni][1]))

        # Pass 3: genuinely removed / added overloads
        for oi, item in enumerate(og):
            if oi not in used_old:
                removed.append(item)
        for ni, item in enumerate(ng):
            if ni not in used_new:
                added.append(item)

    return paired, removed, added


def run_structural_code_analysis(extraction: RawRangeExtraction) -> StructuralAnalysisResult:
    """Run deterministic Python AST and multi-language signature diffing, caller blast-radius scan, dynamic call scan, and doc-drift detection."""
    symbol_changes: list[SymbolSignatureChange] = []
    modified_symbol_names: set[str] = set()
    new_py_symbols_by_qname: dict[str, _PySymbolInfo] = {}
    symbol_owners: dict[tuple[str, str], str] = {}
    symbol_arity_bounds: dict[tuple[str, str], tuple[int, int, bool]] = {}
    init_reexports = _collect_init_reexports(extraction)

    next_ev_num = len(extraction.evidence_registry) + 1
    commit_by_file: dict[str, tuple[str, str]] = {}
    for c in extraction.commits:
        for cf in c.changed_files:
            norm_cf = cf.replace("\\", "/")
            if norm_cf not in commit_by_file:
                commit_by_file[norm_cf] = (c.commit_hash, c.subject)

    def _register_symbol_evidence(
        file_delta_path: str,
        base_span: LineSpan | None,
        target_span: LineSpan | None,
        excerpt: str,
        reason: str,
    ) -> str:
        nonlocal next_ev_num
        eid = f"ev_{next_ev_num:03d}"
        next_ev_num += 1
        norm_delta = file_delta_path.replace("\\", "/")
        default_hash = (
            extraction.commits[0].commit_hash
            if extraction.resolved_target_sha == "WORKING_TREE" and extraction.commits
            else extraction.resolved_target_sha
        )
        default_msg = (
            extraction.commits[0].subject
            if extraction.resolved_target_sha == "WORKING_TREE" and extraction.commits
            else "Working tree or revision diff"
        )
        c_hash, c_msg = commit_by_file.get(norm_delta, (default_hash, default_msg))
        extraction.evidence_registry[eid] = EvidenceRecord(
            evidence_id=eid,
            commit_hash=c_hash,
            commit_message=c_msg,
            file_path=file_delta_path,
            base_line_span=base_span,
            target_line_span=target_span,
            diff_hunk_header=f"AST Symbol Diff ({file_delta_path})",
            diff_excerpt=excerpt[:600],
            reason_supports_finding=reason,
            confidence="high",
        )
        return eid

    # Pre-collect target symbols across non-Python files to detect cross-header/module relocations (BUG-032)
    all_target_multilang_symbols: dict[str, set[str]] = {}
    for t_path, t_blob in extraction.target_blobs.items():
        if t_path.endswith(SUPPORTED_NON_PY_CODE_EXTS) and t_blob:
            for sym_k in _parse_multilang_symbols(t_blob, t_path):
                all_target_multilang_symbols.setdefault(sym_k, set()).add(t_path)

    for fdelta in extraction.changed_files:
        fpath = fdelta.file_path
        if fdelta.is_test_file or fdelta.is_doc_file:
            continue

        base_src = extraction.base_blobs.get(fpath, "")
        target_src = extraction.target_blobs.get(fpath, "")

        # Guard against asymmetric blob loads on modified files (e.g. one side > MAX_SOURCE_BLOB_BYTES) (BUG-032)
        if fdelta.status == "modified" and (not base_src or not target_src):
            continue

        # Skip pure CRLF / line-ending normalization diffs with identical normalized text
        if fdelta.status == "modified" and base_src.replace("\r\n", "\n") == target_src.replace("\r\n", "\n"):
            continue

        lang_family = get_language_family(fpath)

        if fpath.endswith(".py"):
            old_syms = _parse_python_symbols(base_src, file_path=fpath, init_reexports=init_reexports) if base_src else {}
            new_syms = _parse_python_symbols(target_src, file_path=fpath, init_reexports=init_reexports) if target_src else {}
            new_py_symbols_by_qname.update(new_syms)

            # 1. Removed symbols
            for qname, old_s in old_syms.items():
                if "." in qname:
                    symbol_owners[(fpath, qname)] = qname.split(".", 1)[0]
                if qname not in new_syms:
                    b_span = LineSpan(start_line=old_s.start_line, end_line=old_s.end_line)
                    reason = f"Public {old_s.symbol_kind} '{qname}' was removed from {fpath}."
                    eid = _register_symbol_evidence(
                        fpath,
                        b_span,
                        None,
                        f"- {old_s.signature_str}",
                        reason,
                    )
                    sc = SymbolSignatureChange(
                        file_path=fpath,
                        symbol_name=qname,
                        symbol_kind=old_s.symbol_kind,  # type: ignore[arg-type]
                        change_kind="removed",
                        old_signature=old_s.signature_str,
                        new_signature=None,
                        is_breaking_candidate=True,
                        is_public_api_export=old_s.is_public_export,
                        public_api_exposure_reason=old_s.export_reason,
                        api_surface="public_external" if old_s.is_public_export else "internal_only",
                        language_family="python",
                        severity="high",
                        details=reason,
                        base_line_span=b_span,
                        target_line_span=None,
                        evidence_ids=[eid, *fdelta.evidence_ids[:1]],
                    )
                    symbol_changes.append(sc)
                    fdelta.symbol_changes.append(sc)
                    modified_symbol_names.add(qname)

            # 2. Added symbols
            for qname, new_s in new_syms.items():
                if "." in qname:
                    symbol_owners[(fpath, qname)] = qname.split(".", 1)[0]
                if qname not in old_syms:
                    t_span = LineSpan(start_line=new_s.start_line, end_line=new_s.end_line)
                    reason = f"Public {new_s.symbol_kind} '{qname}' was added in {fpath}."
                    eid = _register_symbol_evidence(
                        fpath,
                        None,
                        t_span,
                        f"+ {new_s.signature_str}",
                        reason,
                    )
                    sc = SymbolSignatureChange(
                        file_path=fpath,
                        symbol_name=qname,
                        symbol_kind=new_s.symbol_kind,  # type: ignore[arg-type]
                        change_kind="added",
                        old_signature=None,
                        new_signature=new_s.signature_str,
                        is_breaking_candidate=False,
                        is_public_api_export=new_s.is_public_export,
                        public_api_exposure_reason=new_s.export_reason,
                        api_surface="public_external" if new_s.is_public_export else "internal_only",
                        language_family="python",
                        severity="low",
                        details=reason,
                        base_line_span=None,
                        target_line_span=t_span,
                        evidence_ids=[eid],
                    )
                    symbol_changes.append(sc)
                    fdelta.symbol_changes.append(sc)
                    modified_symbol_names.add(qname)

                    for rec_kind, rec_brk, rec_sev, rec_details in _build_added_symbol_recursion_issues(fpath, new_s):
                        rec_eid = _register_symbol_evidence(
                            fpath,
                            None,
                            t_span,
                            f"+ {new_s.signature_str}",
                            rec_details,
                        )
                        rec_sc = SymbolSignatureChange(
                            file_path=fpath,
                            symbol_name=qname,
                            symbol_kind=new_s.symbol_kind,  # type: ignore[arg-type]
                            change_kind=rec_kind,  # type: ignore[arg-type]
                            old_signature=None,
                            new_signature=new_s.signature_str,
                            is_breaking_candidate=rec_brk,
                            is_public_api_export=new_s.is_public_export,
                            public_api_exposure_reason=new_s.export_reason,
                            api_surface="public_external" if new_s.is_public_export else "internal_only",
                            language_family="python",
                            severity=rec_sev,  # type: ignore[arg-type]
                            details=rec_details,
                            base_line_span=None,
                            target_line_span=t_span,
                            evidence_ids=[rec_eid, *fdelta.evidence_ids[:1]],
                        )
                        symbol_changes.append(rec_sc)
                        fdelta.symbol_changes.append(rec_sc)

            # 3. Modified symbols
            for qname in old_syms.keys() & new_syms.keys():
                old_s = old_syms[qname]
                new_s = new_syms[qname]
                if "." in qname:
                    symbol_owners[(fpath, qname)] = qname.split(".", 1)[0]
                if old_s.body_ast_dump != new_s.body_ast_dump:
                    modified_symbol_names.add(qname)
                diffs = _compare_python_symbol(fpath, old_s, new_s)
                unit_issue = _detect_unit_shift_risk(fpath, old_s, new_s)
                if unit_issue is not None:
                    diffs.append(unit_issue)
                for change_kind, is_brk, sev, details in diffs:
                    b_span = LineSpan(start_line=old_s.start_line, end_line=old_s.end_line)
                    t_span = LineSpan(start_line=new_s.start_line, end_line=new_s.end_line)
                    eid = _register_symbol_evidence(
                        fpath,
                        b_span,
                        t_span,
                        f"- {old_s.signature_str}\n+ {new_s.signature_str}",
                        details,
                    )
                    is_pub_exp = old_s.is_public_export or new_s.is_public_export
                    pub_exp_reason = new_s.export_reason or old_s.export_reason
                    sc = SymbolSignatureChange(
                        file_path=fpath,
                        symbol_name=qname,
                        symbol_kind=new_s.symbol_kind,  # type: ignore[arg-type]
                        change_kind=change_kind,  # type: ignore[arg-type]
                        old_signature=old_s.signature_str,
                        new_signature=new_s.signature_str,
                        is_breaking_candidate=is_brk,
                        is_public_api_export=is_pub_exp,
                        public_api_exposure_reason=pub_exp_reason,
                        api_surface="public_external" if is_pub_exp else "internal_only",
                        language_family="python",
                        severity=sev,  # type: ignore[arg-type]
                        details=details,
                        base_line_span=b_span,
                        target_line_span=t_span,
                        evidence_ids=[eid, *fdelta.evidence_ids[:1]],
                    )
                    symbol_changes.append(sc)
                    fdelta.symbol_changes.append(sc)
                    modified_symbol_names.add(qname)

        elif fpath.endswith(SUPPORTED_NON_PY_CODE_EXTS):
            old_ts = _parse_multilang_symbols_rich(base_src, fpath) if base_src else {}
            new_ts = _parse_multilang_symbols_rich(target_src, fpath) if target_src else {}
            old_rec_info = detect_multilang_recursive_functions(base_src, fpath) if base_src else {}
            rec_info = detect_multilang_recursive_functions(target_src, fpath) if target_src else {}
            has_forwarding_include = bool(
                target_src
                and (
                    "#include " in target_src
                    or "export *" in target_src
                    or "export {" in target_src
                )
            )
            is_compiled = lang_family in _COMPILED_LANGUAGE_FAMILIES
            paired_ml, removed_ml, added_ml = _pair_multilang_overloads(lang_family, old_ts, new_ts)

            # 1. Removed symbols
            for name, old_sym in removed_ml:
                if old_sym.owner_type:
                    symbol_owners[(fpath, name)] = old_sym.owner_type
                symbol_arity_bounds[(fpath, name)] = (
                    old_sym.required_param_count,
                    len(old_sym.params),
                    _is_ml_variadic(old_sym),
                )
                b_span = LineSpan(start_line=old_sym.start_line, end_line=old_sym.end_line)
                base_lookup = name.split("#", 1)[0]
                relocated_set = all_target_multilang_symbols.get(name, set()) | all_target_multilang_symbols.get(base_lookup, set())
                relocated_to = sorted(relocated_set - {fpath})
                is_relocated_forwarded = bool(relocated_to and has_forwarding_include)
                is_pub_exp = old_sym.is_public_api
                api_surf = "public_external" if is_pub_exp else "internal_only"
                is_brk = (not is_relocated_forwarded) and (is_pub_exp or not is_compiled)
                sev = "high" if is_brk else "low"
                if is_relocated_forwarded:
                    reason = f"Symbol {old_sym.symbol_kind} '{name}' was relocated from {fpath} to {relocated_to[0]} with header/module forwarding."
                elif not is_pub_exp and is_compiled:
                    reason = f"Internal/non-public {old_sym.symbol_kind} '{name}' was removed from {fpath} (compiled-language internal symbol)."
                else:
                    reason = f"Exported {old_sym.symbol_kind} '{name}' was removed from {fpath}."
                eid = _register_symbol_evidence(fpath, b_span, None, f"- {old_sym.signature_str}", reason)
                sc = SymbolSignatureChange(
                    file_path=fpath,
                    symbol_name=name,
                    symbol_kind=old_sym.symbol_kind,  # type: ignore[arg-type]
                    change_kind="removed",
                    old_signature=old_sym.signature_str,
                    new_signature=None,
                    is_breaking_candidate=is_brk,
                    is_public_api_export=is_pub_exp,
                    public_api_exposure_reason=old_sym.export_reason,
                    api_surface=api_surf,  # type: ignore[arg-type]
                    language_family=lang_family,
                    severity=sev,  # type: ignore[arg-type]
                    details=reason,
                    base_line_span=b_span,
                    evidence_ids=[eid],
                )
                symbol_changes.append(sc)
                fdelta.symbol_changes.append(sc)
                modified_symbol_names.add(name)

            # 2. Modified symbols (order-independent overload pairing)
            for name, old_sym, new_sym in paired_ml:
                owner_resolved = new_sym.owner_type or old_sym.owner_type
                if owner_resolved:
                    symbol_owners[(fpath, name)] = owner_resolved
                symbol_arity_bounds[(fpath, name)] = (
                    min(old_sym.required_param_count, new_sym.required_param_count),
                    max(len(old_sym.params), len(new_sym.params)),
                    _is_ml_variadic(old_sym) or _is_ml_variadic(new_sym),
                )
                _, old_rec_errors = old_rec_info.get(name, old_rec_info.get(old_sym.qualified_name, (False, [])))
                _, rec_errors = rec_info.get(name, (False, []))
                cmp_res = _semantic_compare_multilang_symbol(
                    lang_family, old_sym, new_sym, old_rec_errors, rec_errors
                )
                if cmp_res is not None:
                    _, raw_brk, raw_sev, extra_note = cmp_res
                    is_pub_exp = old_sym.is_public_api or new_sym.is_public_api
                    api_surf = "public_external" if is_pub_exp else "internal_only"
                    has_rec_bug = bool(rec_errors and not old_rec_errors)
                    # Suppress breaking noise for non-public compiled-language symbols unless recursive defect
                    if is_compiled and not is_pub_exp and not has_rec_bug:
                        is_brk = False
                        sev = "low"
                    else:
                        is_brk = raw_brk
                        sev = raw_sev

                    b_span = LineSpan(start_line=old_sym.start_line, end_line=old_sym.end_line)
                    t_span = LineSpan(start_line=new_sym.start_line, end_line=new_sym.end_line)
                    vis_label = "Exported" if is_pub_exp else "Internal"
                    reason = (
                        f"{vis_label} {new_sym.symbol_kind} '{name}' signature changed from "
                        f"'{old_sym.signature_str}' to '{new_sym.signature_str}'.{extra_note}"
                    ).strip()
                    eid = _register_symbol_evidence(
                        fpath, b_span, t_span, f"- {old_sym.signature_str}\n+ {new_sym.signature_str}", reason
                    )
                    sc = SymbolSignatureChange(
                        file_path=fpath,
                        symbol_name=name,
                        symbol_kind=new_sym.symbol_kind,  # type: ignore[arg-type]
                        change_kind="signature_changed",
                        old_signature=old_sym.signature_str,
                        new_signature=new_sym.signature_str,
                        is_breaking_candidate=is_brk,
                        is_public_api_export=is_pub_exp,
                        public_api_exposure_reason=new_sym.export_reason or old_sym.export_reason,
                        api_surface=api_surf,  # type: ignore[arg-type]
                        language_family=lang_family,
                        severity=sev,  # type: ignore[arg-type]
                        details=reason,
                        base_line_span=b_span,
                        target_line_span=t_span,
                        evidence_ids=[eid],
                    )
                    symbol_changes.append(sc)
                    fdelta.symbol_changes.append(sc)
                    modified_symbol_names.add(name)

            # 3. Added symbols
            for name, new_sym in added_ml:
                if new_sym.owner_type:
                    symbol_owners[(fpath, name)] = new_sym.owner_type
                symbol_arity_bounds[(fpath, name)] = (
                    new_sym.required_param_count,
                    len(new_sym.params),
                    _is_ml_variadic(new_sym),
                )
                t_span = LineSpan(start_line=new_sym.start_line, end_line=new_sym.end_line)
                is_pub_exp = new_sym.is_public_api
                api_surf = "public_external" if is_pub_exp else "internal_only"
                vis_label = "Public" if is_pub_exp else "Internal"
                reason = f"{vis_label} {new_sym.symbol_kind} '{name}' was added in {fpath}."
                eid = _register_symbol_evidence(fpath, None, t_span, f"+ {new_sym.signature_str}", reason)
                sc = SymbolSignatureChange(
                    file_path=fpath,
                    symbol_name=name,
                    symbol_kind=new_sym.symbol_kind,  # type: ignore[arg-type]
                    change_kind="added",
                    old_signature=None,
                    new_signature=new_sym.signature_str,
                    is_breaking_candidate=False,
                    is_public_api_export=is_pub_exp,
                    public_api_exposure_reason=new_sym.export_reason,
                    api_surface=api_surf,  # type: ignore[arg-type]
                    language_family=lang_family,
                    severity="low",
                    details=reason,
                    target_line_span=t_span,
                    evidence_ids=[eid],
                )
                symbol_changes.append(sc)
                fdelta.symbol_changes.append(sc)
                modified_symbol_names.add(name)

                _, rec_errors = rec_info.get(name, (False, []))
                if rec_errors:
                    rec_reason = f"Broken recursive self-call in `{name}` ({fpath}): {rec_errors[0]}"
                    rec_eid = _register_symbol_evidence(fpath, None, t_span, f"+ {new_sym.signature_str}", rec_reason)
                    rec_sc = SymbolSignatureChange(
                        file_path=fpath,
                        symbol_name=name,
                        symbol_kind=new_sym.symbol_kind,  # type: ignore[arg-type]
                        change_kind="signature_changed",
                        old_signature=None,
                        new_signature=new_sym.signature_str,
                        is_breaking_candidate=True,
                        is_public_api_export=is_pub_exp,
                        public_api_exposure_reason=new_sym.export_reason,
                        api_surface=api_surf,  # type: ignore[arg-type]
                        language_family=lang_family,
                        severity="high",
                        details=rec_reason,
                        target_line_span=t_span,
                        evidence_ids=[rec_eid],
                    )
                    symbol_changes.append(rec_sc)
                    fdelta.symbol_changes.append(rec_sc)

    (
        caller_impacts_by_key,
        caller_totals_by_key,
        untested_symbols,
        doc_drift_items,
        unresolved_dynamic_calls,
        coverage_report,
    ) = _scan_callers_and_tests_and_docs(
        extraction,
        symbol_changes,
        modified_symbol_names,
        new_py_symbols_by_qname=new_py_symbols_by_qname,
        symbol_owners=symbol_owners,
        symbol_arity_bounds=symbol_arity_bounds,
    )

    caller_impacts: dict[str, list[CallerImpactItem]] = {}
    for (_fpath_k, sym_k), clist in caller_impacts_by_key.items():
        if sym_k not in caller_impacts or len(clist) > len(caller_impacts[sym_k]):
            caller_impacts[sym_k] = clist

    # Assemble deterministic PotentialBreakingChangeFinding objects (requires human review!)
    breaking_findings: list[PotentialBreakingChangeFinding] = []
    b_idx = 1
    for sc in symbol_changes:
        if not sc.is_breaking_candidate:
            continue
        fid = f"brk_{b_idx:03d}"
        b_idx += 1
        comp_key = (sc.file_path, sc.symbol_name)
        callers = caller_impacts_by_key.get(comp_key, [])
        total_matched = caller_totals_by_key.get(comp_key, len(callers))
        related_drift = [d for d in doc_drift_items if d.referenced_symbol == sc.symbol_name]
        related_dynamic = [
            d
            for d in unresolved_dynamic_calls
            if d.referenced_symbol_hint in (None, sc.symbol_name)
        ]

        observed_facts = [
            f"In '{sc.file_path}', symbol '{sc.symbol_name}' ({sc.symbol_kind}) underwent '{sc.change_kind}'.",
            sc.details,
        ]
        if sc.old_signature:
            observed_facts.append(f"Base signature: `{sc.old_signature}`")
        if sc.new_signature:
            observed_facts.append(f"Target signature: `{sc.new_signature}`")
        if sc.is_public_api_export:
            observed_facts.append(
                f"Public API Export Exposure: `{sc.symbol_name}` is publicly exported ({sc.public_api_exposure_reason})."
            )
        if callers:
            broken_callers = [c for c in callers if c.arity_mismatch_detected]
            count_note = f"{total_matched}" if total_matched <= len(callers) else f"{total_matched} ({len(callers)} shown)"
            caller_summary = (
                f"Detected {count_note} downstream call site(s) in repository "
                f"({len(broken_callers)} with proven argument/arity incompatibility: "
                f"{', '.join(f'{c.caller_file}:{c.line_number}' for c in callers[:3])})."
            )
            observed_facts.append(caller_summary)
        if related_drift:
            observed_facts.append(
                f"Detected {len(related_drift)} potentially stale documentation reference(s) (e.g., {', '.join(f'{d.doc_file}:{d.line_number}' for d in related_drift[:2])})."
            )
        if related_dynamic:
            observed_facts.append(
                f"Detected {len(related_dynamic)} unresolved dynamic/reflective invocation(s) in repository (e.g., {', '.join(f'{d.file_path}:{d.line_number}' for d in related_dynamic[:2])})."
            )

        risks = [
            "Requires human review: External callers or plugins invoking the previous signature may fail at runtime with TypeError, AttributeError, or unexpected behavior.",
        ]
        if sc.is_public_api_export:
            risks.append(
                f"[PUBLIC API EXPORT] `{sc.symbol_name}` is part of the public API surface ({sc.public_api_exposure_reason}): external downstream consumers outside this repository may break even when internal callers are updated."
            )
        if related_dynamic:
            risks.append(
                f"[UNRESOLVED DYNAMIC CALLS] {len(related_dynamic)} dynamic/reflective call site(s) (getattr/eval/dispatch) exist in the repository that static AST analysis cannot rule out."
            )
        if sc.symbol_name in untested_symbols:
            risks.append(f"Symbol '{sc.symbol_name}' has no detected references in the repository test suite.")
        if related_drift:
            risks.append("Documentation examples referencing this symbol may fail when copy-pasted by users.")

        breaking_findings.append(
            PotentialBreakingChangeFinding(
                finding_id=fid,
                title=f"Potential Breaking Change in `{sc.symbol_name}` ({sc.change_kind}) — Requires Human Review",
                severity=sc.severity,
                confidence="high" if sc.change_kind in ("removed", "signature_changed") else "medium",
                uncertainty_notes="Static AST signature analysis verifies structural contract changes, but runtime dynamic dispatch or external consumer usage requires human review.",
                affected_symbol=sc.symbol_name,
                file_path=sc.file_path,
                change_kind=sc.change_kind,
                old_signature=sc.old_signature,
                new_signature=sc.new_signature,
                is_public_api_export=sc.is_public_api_export,
                public_api_exposure_reason=sc.public_api_exposure_reason,
                api_surface=sc.api_surface,
                language_family=sc.language_family,
                observed_facts=observed_facts,
                model_interpretation=(
                    f"Deterministic AST analysis flagged `{sc.symbol_name}` in `{sc.file_path}` as a potential breaking change ({sc.details}). "
                    "Review callers, public export boundaries, and migration notes before release."
                ),
                potential_risks_requiring_verification=risks,
                affected_callers=callers,
                total_callers_matched=total_matched,
                unresolved_dynamic_calls=related_dynamic[:5],
                doc_drift=related_drift,
                evidence_ids=list(dict.fromkeys(sc.evidence_ids)),
                evidence=[
                    extraction.evidence_registry[eid]
                    for eid in dict.fromkeys(sc.evidence_ids)
                    if eid in extraction.evidence_registry
                ],
            )
        )

    # Also check commits that explicitly declare BREAKING CHANGE in commit message even if no AST symbol matched
    for c in extraction.commits:
        if c.declares_breaking_in_message:
            already_covered = any(
                any(ev.commit_hash == c.commit_hash for ev in bf.evidence) for bf in breaking_findings
            )
            if not already_covered:
                eid = f"ev_{next_ev_num:03d}"
                next_ev_num += 1
                target_file = c.changed_files[0] if c.changed_files else "COMMIT_MESSAGE"
                extraction.evidence_registry[eid] = EvidenceRecord(
                    evidence_id=eid,
                    commit_hash=c.commit_hash,
                    commit_message=c.subject,
                    file_path=target_file,
                    diff_excerpt=f"{c.subject}\n{c.body}".strip()[:500],
                    reason_supports_finding="Commit message explicitly declares a breaking change ('!' or 'BREAKING CHANGE:').",
                    confidence="medium",
                )
                fid = f"brk_{b_idx:03d}"
                b_idx += 1
                breaking_findings.append(
                    PotentialBreakingChangeFinding(
                        finding_id=fid,
                        title=f"Commit `{c.short_hash}` Declares Potential Breaking Change — Requires Human Review",
                        severity="medium",
                        confidence="medium",
                        uncertainty_notes="Declared via Conventional Commit marker ('!' or 'BREAKING CHANGE:'); verify actual behavioral impact in diff.",
                        affected_symbol=None,
                        file_path=target_file,
                        change_kind="declared_in_commit",
                        observed_facts=[
                            f"Commit `{c.commit_hash[:12]}` ('{c.subject}') includes an explicit breaking-change indicator.",
                            f"Modified files in commit: {', '.join(c.changed_files[:5]) or 'none'}.",
                        ],
                        model_interpretation="Commit author explicitly marked this change as potentially breaking.",
                        potential_risks_requiring_verification=[
                            "Requires human review to confirm behavioral migration requirements for downstream users."
                        ],
                        evidence_ids=[eid],
                        evidence=[extraction.evidence_registry[eid]],
                    )
                )

    return StructuralAnalysisResult(
        symbol_changes=symbol_changes,
        caller_impacts=caller_impacts,
        doc_drift_items=doc_drift_items,
        untested_modified_symbols=untested_symbols,
        unresolved_dynamic_calls=unresolved_dynamic_calls,
        analysis_coverage=coverage_report,
        deterministic_breaking_findings=breaking_findings,
    )


def analyze_python_module_diff(
    old_code: str,
    new_code: str,
    file_path: str = "module.py",
) -> StructuralAnalysisResult:
    """Analyze changes between two versions of a Python source file directly."""
    old_syms = _parse_python_symbols(old_code, file_path=file_path) if old_code else {}
    new_syms = _parse_python_symbols(new_code, file_path=file_path) if new_code else {}

    symbol_changes: list[SymbolSignatureChange] = []

    # 1. Removed symbols
    for qname, old_s in old_syms.items():
        if qname not in new_syms:
            b_span = LineSpan(start_line=old_s.start_line, end_line=old_s.end_line)
            reason = f"Public {old_s.symbol_kind} '{qname}' was removed from {file_path}."
            sc = SymbolSignatureChange(
                file_path=file_path,
                symbol_name=qname,
                symbol_kind=old_s.symbol_kind,  # type: ignore[arg-type]
                change_kind="removed",
                old_signature=old_s.signature_str,
                new_signature=None,
                is_breaking_candidate=True,
                is_public_api_export=old_s.is_public_export,
                public_api_exposure_reason=old_s.export_reason,
                severity="high",
                details=reason,
                base_line_span=b_span,
                target_line_span=None,
                evidence_ids=[],
            )
            symbol_changes.append(sc)

    # 2. Added symbols
    for qname, new_s in new_syms.items():
        if qname not in old_syms:
            t_span = LineSpan(start_line=new_s.start_line, end_line=new_s.end_line)
            reason = f"Public {new_s.symbol_kind} '{qname}' was added in {file_path}."
            sc = SymbolSignatureChange(
                file_path=file_path,
                symbol_name=qname,
                symbol_kind=new_s.symbol_kind,  # type: ignore[arg-type]
                change_kind="added",
                old_signature=None,
                new_signature=new_s.signature_str,
                is_breaking_candidate=False,
                is_public_api_export=new_s.is_public_export,
                public_api_exposure_reason=new_s.export_reason,
                severity="low",
                details=reason,
                base_line_span=None,
                target_line_span=t_span,
                evidence_ids=[],
            )
            symbol_changes.append(sc)
            for rec_kind, rec_brk, rec_sev, rec_details in _build_added_symbol_recursion_issues(file_path, new_s):
                symbol_changes.append(
                    SymbolSignatureChange(
                        file_path=file_path,
                        symbol_name=qname,
                        symbol_kind=new_s.symbol_kind,  # type: ignore[arg-type]
                        change_kind=rec_kind,  # type: ignore[arg-type]
                        old_signature=None,
                        new_signature=new_s.signature_str,
                        is_breaking_candidate=rec_brk,
                        is_public_api_export=new_s.is_public_export,
                        public_api_exposure_reason=new_s.export_reason,
                        severity=rec_sev,  # type: ignore[arg-type]
                        details=rec_details,
                        base_line_span=None,
                        target_line_span=t_span,
                        evidence_ids=[],
                    )
                )

    # 3. Modified symbols
    for qname in old_syms.keys() & new_syms.keys():
        old_s = old_syms[qname]
        new_s = new_syms[qname]
        diffs = _compare_python_symbol(file_path, old_s, new_s)
        for change_kind, is_brk, sev, details in diffs:
            b_span = LineSpan(start_line=old_s.start_line, end_line=old_s.end_line)
            t_span = LineSpan(start_line=new_s.start_line, end_line=new_s.end_line)
            sc = SymbolSignatureChange(
                file_path=file_path,
                symbol_name=qname,
                symbol_kind=new_s.symbol_kind,  # type: ignore[arg-type]
                change_kind=change_kind,  # type: ignore[arg-type]
                old_signature=old_s.signature_str,
                new_signature=new_s.signature_str,
                is_breaking_candidate=is_brk,
                is_public_api_export=old_s.is_public_export or new_s.is_public_export,
                public_api_exposure_reason=new_s.export_reason or old_s.export_reason,
                severity=sev,  # type: ignore[arg-type]
                details=details,
                base_line_span=b_span,
                target_line_span=t_span,
                evidence_ids=[],
            )
            symbol_changes.append(sc)

    return StructuralAnalysisResult(symbol_changes=symbol_changes)


def find_affected_callers_in_tree(
    repo_path: Path,
    symbol_name: str,
) -> list[CallerImpactItem]:
    """Scan tree for AST call sites of symbol_name across Python files."""
    callers: list[CallerImpactItem] = []
    short_name = symbol_name.split(".")[-1]

    for py_file in repo_path.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
            lines = content.splitlines()
            line_map = _build_line_to_enclosing_symbol(tree)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    callee_name = None
                    if isinstance(node.func, ast.Name):
                        callee_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        callee_name = node.func.attr
                    if callee_name == short_name:
                        line_no = getattr(node, "lineno", 1)
                        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                        rel_path = str(py_file.relative_to(repo_path)).replace("\\", "/")
                        callers.append(
                            CallerImpactItem(
                                caller_file=rel_path,
                                caller_symbol=short_name,
                                enclosing_symbol=line_map.get(line_no),
                                line_number=line_no,
                                call_snippet=snippet,
                                resolution_confidence="exact_ast",
                            )
                        )
        except (OSError, RecursionError, SyntaxError, ValueError):
            continue
    return callers


def detect_python_doc_drift(
    code: str,
    file_path: str = "module.py",
) -> list[DocDriftItem]:
    """Detect discrepancies between docstring parameters and actual function signatures."""
    drift_items: list[DocDriftItem] = []
    try:
        tree = ast.parse(code)
    except Exception:
        return drift_items

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node)
            if not doc:
                continue
            actual_params = {arg.arg for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs}
            param_matches = re.findall(r":param\s+([A-Za-z0-9_]+):", doc)
            for p in param_matches:
                if p not in actual_params:
                    drift_items.append(
                        DocDriftItem(
                            doc_file=file_path,
                            line_number=getattr(node, "lineno", 1),
                            referenced_symbol=node.name,
                            snippet=f":param {p}:",
                            drift_reason=f"Docstring for '{node.name}' documents parameter '{p}' which does not exist in function signature.",
                            evidence_ids=[],
                        )
                    )
    return drift_items
