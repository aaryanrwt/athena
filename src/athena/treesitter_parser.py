"""Optional Tree-sitter multi-language AST symbol and call-site parser.

Supports 14 non-Python languages via ``tree-sitter`` and
``tree-sitter-language-pack`` with modifier canonicalization, per-language
visibility analysis, qualified owner resolution, and comment/declaration-free
call-site extraction. Falls back cleanly to structural parsing when
uninstalled or when ``ATHENA_TREESITTER_DISABLE=1`` is set.
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any

_PARSER_LOCK = threading.Lock()
_LANG_OBJ_CACHE: dict[str, Any] = {}
_FAILED_LANGS: set[str] = set()

_EXT_TO_TS_LANG: dict[str, str] = {
    ".ts": "typescript",
    ".tsx": "tsx",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".cs": "csharp",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
}

_EXT_TO_FAMILY: dict[str, str] = {
    ".py": "python",
    ".ts": "ts_js",
    ".tsx": "ts_js",
    ".mts": "ts_js",
    ".cts": "ts_js",
    ".js": "ts_js",
    ".jsx": "ts_js",
    ".mjs": "ts_js",
    ".cjs": "ts_js",
    ".c": "c_cpp",
    ".cc": "c_cpp",
    ".cpp": "c_cpp",
    ".cxx": "c_cpp",
    ".h": "c_cpp",
    ".hh": "c_cpp",
    ".hpp": "c_cpp",
    ".hxx": "c_cpp",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
}

MODIFIER_TOKENS: frozenset[str] = frozenset(
    {
        "public",
        "protected",
        "private",
        "internal",
        "file",
        "fileprivate",
        "open",
        "async",
        "override",
        "virtual",
        "static",
        "abstract",
        "final",
        "sealed",
        "readonly",
        "extern",
        "unsafe",
        "new",
        "partial",
        "synchronized",
        "native",
        "strictfp",
        "inline",
        "constexpr",
        "consteval",
        "explicit",
        "friend",
        "suspend",
        "export",
        "default",
        "declare",
        "mutating",
        "nonmutating",
        "required",
        "convenience",
        "dynamic",
        "infix",
        "operator",
        "tailrec",
    }
)

_VISIBILITY_TOKENS = frozenset({"public", "protected", "private", "internal", "fileprivate", "open", "file"})

_CPP_SKIP_NAMES = frozenset(
    {
        "if",
        "else",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "sizeof",
        "alignof",
        "decltype",
        "static_assert",
        "assert",
        "defined",
        "elif",
        "pragma",
        "include",
        "define",
        "undef",
        "typename",
        "template",
        "new",
        "delete",
        "throw",
        "try",
        "namespace",
        "using",
    }
)

_JS_SKIP_NAMES = frozenset(
    {
        "if",
        "else",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "function",
        "constructor",
        "super",
        "import",
        "export",
        "typeof",
        "instanceof",
        "await",
    }
)

_CPP_CLASS_MACRO_RE = re.compile(
    r"\b(class|struct|enum(?:\s+class)?)\s+([A-Z][A-Z0-9_]{2,}(?:\([^)\n]*\))?)\s+(?=[A-Za-z_]\w*(?:\s+final)?\s*(?::|\{))"
)
_CPP_LEADING_EXPORT_MACRO_RE = re.compile(
    r"(?m)^([ \t]*)((?:[A-Z][A-Z0-9_]*(?:_API|_EXPORT|_EXPORTS|_DLL|_PUBLIC|_IMPORT|_EXTERN|_VISIBLE)|GRPCAPI|CUBLASAPI|CUDA_HOST_DEVICE|__declspec\s*\([^)\n]*\)|__attribute__\s*\(\([^)\n]*\)\)))(?=[ \t]+[A-Za-z_])"
)


def _preprocess_cpp_export_macros(source: str) -> str:
    """Blank out C/C++ visibility/export attribute macros in-place, preserving byte offsets and line numbers."""
    out = _CPP_CLASS_MACRO_RE.sub(lambda m: f"{m.group(1)} {' ' * len(m.group(2))} ", source)
    out = _CPP_LEADING_EXPORT_MACRO_RE.sub(lambda m: f"{m.group(1)}{' ' * len(m.group(2))}", out)
    return out


@dataclass
class ParsedMultiLangSymbol:
    """Normalized structural representation of a non-Python code symbol."""

    qualified_name: str
    short_name: str
    owner_type: str | None
    symbol_kind: str
    start_line: int
    end_line: int
    visibility: str  # "public" | "protected" | "internal" | "private"
    is_public_api: bool
    export_reason: str
    modifiers: frozenset[str] = field(default_factory=frozenset)
    params: list[str] = field(default_factory=list)
    normalized_param_types: list[str] = field(default_factory=list)
    required_param_count: int = 0
    return_type: str | None = None
    signature_str: str = ""
    parser_backend: str = "structural_fallback"


@dataclass
class ParsedCallSite:
    """Call invocation extracted from source code."""

    callee_name: str
    receiver: str | None
    line_number: int
    arg_count: int | None
    call_snippet: str


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def get_language_family(file_path: str) -> str:
    """Map a file extension to a canonical language family identifier."""
    low = file_path.lower()
    dot = low.rfind(".")
    if dot == -1:
        return ""
    return _EXT_TO_FAMILY.get(low[dot:], "")


def get_treesitter_language_name(file_path: str) -> str | None:
    """Return the tree-sitter grammar name for a source path, if supported."""
    low = file_path.lower()
    dot = low.rfind(".")
    if dot == -1:
        return None
    return _EXT_TO_TS_LANG.get(low[dot:])


def is_treesitter_available() -> bool:
    """Return True when tree-sitter packages are importable and not disabled by env."""
    if _env_truthy("ATHENA_TREESITTER_DISABLE"):
        return False
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_language_pack  # noqa: F401

        return True
    except ImportError:
        return False


def get_treesitter_status() -> dict[str, Any]:
    """Report runtime availability and configured backend for Tree-sitter parsing."""
    disabled = _env_truthy("ATHENA_TREESITTER_DISABLE")
    available = is_treesitter_available()
    return {
        "available": available,
        "disabled_by_env": disabled,
        "backend": "tree_sitter" if available else "structural_fallback",
        "supported_languages": sorted(set(_EXT_TO_TS_LANG.values())),
    }


def _get_ts_language(lang_name: str) -> Any | None:
    if _env_truthy("ATHENA_TREESITTER_DISABLE"):
        return None
    with _PARSER_LOCK:
        if lang_name in _LANG_OBJ_CACHE:
            return _LANG_OBJ_CACHE[lang_name]
        if lang_name in _FAILED_LANGS:
            return None
    try:
        import tree_sitter_language_pack as lp

        if _env_truthy("ATHENA_TREESITTER_OFFLINE") and lang_name not in lp.downloaded_languages():
            return None
        lang_obj = lp.get_language(lang_name)
    except Exception:
        with _PARSER_LOCK:
            _FAILED_LANGS.add(lang_name)
        return None
    with _PARSER_LOCK:
        _LANG_OBJ_CACHE[lang_name] = lang_obj
    return lang_obj


def _parse_tree(source: str, lang_name: str) -> tuple[Any, bytes] | tuple[None, None]:
    lang_obj = _get_ts_language(lang_name)
    if lang_obj is None:
        return None, None
    try:
        from tree_sitter import Parser

        parser = Parser(lang_obj)
        src_bytes = source.encode("utf-8", errors="replace")
        tree = parser.parse(src_bytes)
        if tree is None or tree.root_node is None:
            return None, None
        return tree, src_bytes
    except Exception:
        return None, None


def _node_text(node: Any, src_bytes: bytes) -> str:
    if node is None:
        return ""
    return src_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def normalize_whitespace(text: str) -> str:
    """Collapse arbitrary whitespace runs into single spaces."""
    return " ".join(text.split())


def split_top_level_comma(text: str) -> list[str]:
    """Split a comma-separated parameter/argument list while respecting nested brackets and strings."""
    cleaned = text.strip()
    if not cleaned:
        return []
    parts: list[str] = []
    start = 0
    depth_paren = 0
    depth_brack = 0
    depth_brace = 0
    depth_angle = 0
    in_quote: str | None = None
    escaped = False

    for idx, ch in enumerate(cleaned):
        if in_quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'", "`"):
            in_quote = ch
        elif ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == "[":
            depth_brack += 1
        elif ch == "]":
            depth_brack = max(0, depth_brack - 1)
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace = max(0, depth_brace - 1)
        elif ch == "<":
            # Avoid treating comparison ops as angle brackets when unlikely, though inside signatures '<' is generic
            depth_angle += 1
        elif ch == ">":
            if idx > 0 and cleaned[idx - 1] == "=":
                continue  # arrow `=>` or lambda
            depth_angle = max(0, depth_angle - 1)
        elif (
            ch == ","
            and depth_paren == 0
            and depth_brack == 0
            and depth_brace == 0
            and depth_angle == 0
        ):
            seg = normalize_whitespace(cleaned[start:idx])
            if seg:
                parts.append(seg)
            start = idx + 1

    tail = normalize_whitespace(cleaned[start:])
    if tail:
        parts.append(tail)
    return parts


def normalize_modifiers_and_return(raw_prefix: str) -> tuple[frozenset[str], str | None]:
    """Separate order-insensitive declaration modifiers from a pure return type string."""
    collapsed = normalize_whitespace(raw_prefix)
    if not collapsed:
        return frozenset(), None

    tokens = collapsed.split()
    mods: list[str] = []
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        low = tok.lower()
        if low in MODIFIER_TOKENS:
            mods.append(low)
            idx += 1
            continue
        # Handle `@Override` / `@Nullable` annotations or `[Attribute]` if present before modifiers
        if tok.startswith("@"):
            mods.append(tok)
            idx += 1
            continue
        break

    rem = " ".join(tokens[idx:]).strip()
    return frozenset(mods), (rem if rem else None)


def resolve_visibility_from_modifiers(
    modifiers: frozenset[str],
    *,
    default_visibility: str = "internal",
) -> str:
    """Resolve canonical visibility tier (`public`, `protected`, `internal`, `private`)."""
    low_mods = {m.lower() for m in modifiers}
    if "private" in low_mods:
        # C# `private protected` is still inaccessible outside assembly/class hierarchy
        return "internal" if "protected" in low_mods else "private"
    if "protected" in low_mods:
        return "protected"
    if "internal" in low_mods or "fileprivate" in low_mods or "file" in low_mods:
        return "internal"
    if "public" in low_mods or "open" in low_mods or "export" in low_mods:
        return "public"
    return default_visibility


def compute_multilang_visibility(
    *,
    family: str,
    file_path: str,
    short_name: str,
    visibility: str,
    modifiers: frozenset[str],
    owner_type: str | None = None,
    has_export: bool = False,
) -> tuple[bool, str]:
    """Compute whether a non-Python declaration belongs to the external public API surface."""
    norm = file_path.replace("\\", "/")
    is_header = norm.lower().endswith((".h", ".hh", ".hpp", ".hxx"))
    stem = norm.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    in_internal_dir = "/internal/" in f"/{norm.lower()}"

    if family == "go":
        clean = short_name.split(".")[-1]
        if in_internal_dir:
            return False, f"Go `internal/` package declaration `{norm}`"
        if clean[:1].isupper():
            return (
                True,
                f"Exported Go API in `{norm}` (external consumers break even when internal build succeeds)",
            )
        return False, f"Unexported lowercase Go symbol `{clean}` in `{norm}`"

    if family == "rust":
        if visibility == "public":
            return (
                True,
                f"Public `pub` Rust item in `{norm}` (external crate consumers may depend on it)",
            )
        return False, f"Crate-private/non-pub Rust item (`{visibility}`) in `{norm}`"

    if family == "ts_js":
        if has_export or "export" in modifiers:
            if visibility == "private":
                return False, f"Private class member in `{norm}`"
            return True, f"Exported TS/JS API in `{norm}`"
        if visibility in ("public", "protected") and not short_name.startswith(("_", "#")):
            return False, f"Non-exported module declaration in `{norm}`"
        return False, f"Private/internal TS/JS member in `{norm}`"

    if family in ("csharp", "java", "kotlin", "scala", "swift"):
        if visibility in ("public", "protected"):
            return (
                True,
                f"`{visibility}` {family} API in `{norm}` (external assembly/package consumers impacted)",
            )
        return False, f"`{visibility}` {family} declaration in `{norm}` (internal to package/assembly)"

    if family == "c_cpp":
        cpp_norm_segs = norm.lower().split("/")[:-1]
        if any(seg in ("internal", "detail", "details", "impl", "private") for seg in cpp_norm_segs):
            return False, f"Internal C/C++ implementation header/file `{norm}`"
        clean = short_name.split("::")[-1]
        if "static" in modifiers or visibility in ("internal", "private") or clean.startswith("_"):
            return False, f"Internal/static/private C/C++ symbol `{short_name}` in `{norm}`"
        if is_header:
            return True, f"Header-declared C/C++ API in `{norm}`"
        return (
            True,
            f"Non-static external-linkage C/C++ definition in `{norm}`",
        )

    if family == "php":
        if visibility in ("public", "protected"):
            return True, f"`{visibility}` PHP declaration in `{norm}`"
        return False, f"`{visibility}` PHP member in `{norm}`"

    if family == "ruby":
        if visibility in ("public", "protected") and not short_name.lstrip("self.").startswith("_"):
            return True, f"Public Ruby declaration in `{norm}`"
        return False, f"`{visibility}` Ruby method in `{norm}`"

    _ = stem
    return visibility in ("public", "protected"), f"{visibility} declaration in `{norm}`"


def _strip_default_value(param_text: str) -> tuple[str, bool]:
    """Split off `= default` at depth 0, returning (declaration_part, has_default)."""
    depth_paren = 0
    depth_brack = 0
    depth_brace = 0
    depth_angle = 0
    in_quote: str | None = None
    escaped = False

    for idx, ch in enumerate(param_text):
        if in_quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'", "`"):
            in_quote = ch
        elif ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == "[":
            depth_brack += 1
        elif ch == "]":
            depth_brack = max(0, depth_brack - 1)
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace = max(0, depth_brace - 1)
        elif ch == "<":
            depth_angle += 1
        elif ch == ">":
            depth_angle = max(0, depth_angle - 1)
        elif (
            ch == "="
            and depth_paren == 0
            and depth_brack == 0
            and depth_brace == 0
            and depth_angle == 0
        ):
            nxt = param_text[idx + 1 : idx + 2]
            prev = param_text[idx - 1 : idx]
            if nxt in ("=", ">") or prev in ("!", "<", ">", "="):
                continue
            return param_text[:idx].strip(), True
    return param_text.strip(), False


def normalize_type_expr(type_text: str) -> str:
    """Normalize whitespace, Java/Kotlin annotations, and punctuation in a type string."""
    s = normalize_whitespace(type_text)
    s = re.sub(r"@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?\s*", "", s)
    s = normalize_whitespace(s)
    s = re.sub(r"\s*([*&,<>:\[\]])\s*", r"\1", s)
    s = s.replace(",", ", ")
    return s.strip()


def extract_param_info_from_text(param_text: str, family: str) -> tuple[str, str, bool]:
    """Extract (cleaned_param_str, normalized_type, is_optional) for structural parameters."""
    decl, has_default = _strip_default_value(param_text)
    is_variadic = (
        decl.startswith("...")
        or " ..." in decl
        or decl.endswith("...")
        or decl.startswith(("params ", "vararg ", "*"))
    )
    is_optional = has_default or is_variadic

    if family in ("ts_js", "rust", "kotlin", "scala", "swift"):
        # Format: `name?: Type` or `name: Type`
        if ":" in decl:
            lhs, rhs = decl.split(":", 1)
            if lhs.strip().endswith("?"):
                is_optional = True
            return normalize_whitespace(param_text), normalize_type_expr(rhs), is_optional
        return normalize_whitespace(param_text), "any", is_optional

    if family == "ruby":
        return normalize_whitespace(param_text), "any", is_optional

    if family == "go":
        # `ctx context.Context`, `s string`, `vals ...string`, or type-only `int`
        toks = decl.split()
        if len(toks) >= 2 and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", toks[0]):
            return normalize_whitespace(param_text), normalize_type_expr(" ".join(toks[1:])), is_optional
        return normalize_whitespace(param_text), normalize_type_expr(decl), is_optional

    if family == "php":
        # `string $a` or `$a` or `?string $a`
        m = re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", decl)
        if m:
            tpart = decl[: m.start()].strip()
            return normalize_whitespace(param_text), normalize_type_expr(tpart) if tpart else "mixed", is_optional
        return normalize_whitespace(param_text), "mixed", is_optional

    # c_cpp / csharp / java: `[modifiers/qualifiers] <Type> [name][[]]`
    no_attr = re.sub(r"^\[[^\]]+\]\s*", "", decl).strip()
    no_attr = re.sub(r"^(?:this|params|ref|out|in|final)\s+", "", no_attr).strip()
    # Handle trailing array brackets attached to param name `int vals[]`
    arr_suffix = ""
    m_arr = re.search(r"(?:\[\s*\])+$", no_attr)
    if m_arr:
        arr_suffix = m_arr.group(0).replace(" ", "")
        no_attr = no_attr[: m_arr.start()].strip()
    m_name = re.search(r"([A-Za-z_][A-Za-z0-9_]*)$", no_attr)
    if m_name and len(no_attr[: m_name.start()].strip()) > 0:
        type_only = no_attr[: m_name.start()].strip() + arr_suffix
        return normalize_whitespace(param_text), normalize_type_expr(type_only), is_optional
    return normalize_whitespace(param_text), normalize_type_expr(no_attr + arr_suffix), is_optional


def _parse_params_from_raw(raw_params: str, family: str) -> tuple[list[str], list[str], int]:
    """Parse raw parameter-list string into (param_items, normalized_types, required_count)."""
    raw_items = split_top_level_comma(raw_params)
    params: list[str] = []
    norm_types: list[str] = []
    req_count = 0

    if family == "go":
        # Handle Go grouped parameters like `owner, repo string`: back-propagate type to preceding bare identifiers.
        pending_bare: list[str] = []
        for item in raw_items:
            toks = item.split()
            if len(toks) == 1 and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", toks[0]):
                pending_bare.append(toks[0])
                continue
            cleaned, ntype, is_opt = extract_param_info_from_text(item, family)
            for ident in pending_bare:
                params.append(f"{ident} {ntype}".strip())
                norm_types.append(ntype)
                if not is_opt:
                    req_count += 1
            pending_bare.clear()
            params.append(cleaned)
            norm_types.append(ntype)
            if not is_opt:
                req_count += 1
        for ident in pending_bare:
            params.append(ident)
            norm_types.append("any")
            req_count += 1
        return params, norm_types, req_count

    for item in raw_items:
        stripped = item.strip()
        if not stripped:
            continue
        if family == "c_cpp" and stripped == "void":
            continue
        if family == "rust" and stripped in ("self", "&self", "&mut self"):
            continue
        cleaned, ntype, is_opt = extract_param_info_from_text(stripped, family)
        params.append(cleaned)
        norm_types.append(ntype)
        if not is_opt:
            req_count += 1

    return params, norm_types, req_count


def _store_symbol(
    symbols: dict[str, ParsedMultiLangSymbol],
    sym: ParsedMultiLangSymbol,
    *,
    allow_overload: bool = False,
) -> None:
    """Insert a symbol cleanly, avoiding silent clobbering across distinct owner types or overloads."""
    key = sym.qualified_name
    existing = symbols.get(key)
    if existing is None:
        symbols[key] = sym
        return
    if existing.owner_type and sym.owner_type and existing.owner_type != sym.owner_type:
        sep = "::" if sym.export_reason and "C/C++" in sym.export_reason else "."
        alt_key = f"{sym.owner_type}{sep}{sym.short_name}"
        if alt_key not in symbols:
            sym.qualified_name = alt_key
            symbols[alt_key] = sym
            return
    if allow_overload and existing.normalized_param_types != sym.normalized_param_types:
        ov_key = f"{key}#{len(sym.params)}"
        idx = len(sym.params)
        while ov_key in symbols:
            idx += 1
            ov_key = f"{key}#{idx}"
        sym.qualified_name = ov_key
        symbols[ov_key] = sym


def _make_symbol(
    *,
    qualified_name: str,
    short_name: str,
    owner_type: str | None,
    symbol_kind: str,
    start_line: int,
    end_line: int,
    family: str,
    file_path: str,
    visibility: str,
    modifiers: frozenset[str],
    params: list[str],
    norm_types: list[str],
    req_count: int,
    return_type: str | None,
    signature_str: str,
    has_export: bool = False,
    backend: str = "tree_sitter",
) -> ParsedMultiLangSymbol:
    is_pub, exp_reason = compute_multilang_visibility(
        family=family,
        file_path=file_path,
        short_name=short_name,
        visibility=visibility,
        modifiers=modifiers,
        owner_type=owner_type,
        has_export=has_export,
    )
    return ParsedMultiLangSymbol(
        qualified_name=qualified_name,
        short_name=short_name,
        owner_type=owner_type,
        symbol_kind=symbol_kind,
        start_line=start_line,
        end_line=end_line,
        visibility=visibility,
        is_public_api=is_pub,
        export_reason=exp_reason,
        modifiers=modifiers,
        params=params,
        normalized_param_types=norm_types,
        required_param_count=req_count,
        return_type=return_type,
        signature_str=signature_str,
        parser_backend=backend,
    )


def _walk_ts_js(root: Any, src_bytes: bytes, file_path: str, syms: dict[str, ParsedMultiLangSymbol]) -> None:
    def _has_export_ancestor(node: Any) -> bool:
        curr = node.parent
        while curr is not None:
            if curr.type == "export_statement":
                return True
            curr = curr.parent
        return False

    def _visit(node: Any, owner: str | None, owner_exported: bool) -> None:
        ntype = node.type
        if ntype in ("class_declaration", "abstract_class_declaration"):
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, src_bytes).strip()
            if name:
                is_exp = owner_exported or _has_export_ancestor(node)
                heritage = ""
                for ch in node.children:
                    if ch.type == "class_heritage":
                        heritage = normalize_whitespace(_node_text(ch, src_bytes))
                mods = frozenset({"export"}) if is_exp else frozenset()
                sig = f"{'export ' if is_exp else ''}class {name}" + (f" {heritage}" if heritage else "")
                _store_symbol(
                    syms,
                    _make_symbol(
                        qualified_name=name,
                        short_name=name,
                        owner_type=None,
                        symbol_kind="class",
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        family="ts_js",
                        file_path=file_path,
                        visibility="public" if is_exp else "internal",
                        modifiers=mods,
                        params=[],
                        norm_types=[],
                        req_count=0,
                        return_type=None,
                        signature_str=sig,
                        has_export=is_exp,
                    ),
                )
                body = node.child_by_field_name("body")
                if body is not None:
                    for ch in body.children:
                        _visit(ch, name, is_exp)
                return

        if ntype in ("interface_declaration", "enum_declaration", "type_alias_declaration"):
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, src_bytes).strip()
            is_exp = owner_exported or _has_export_ancestor(node)
            if name and is_exp:
                kind_name = "enum" if ntype == "enum_declaration" else "interface"
                kw = "enum" if kind_name == "enum" else ("type" if ntype == "type_alias_declaration" else "interface")
                _store_symbol(
                    syms,
                    _make_symbol(
                        qualified_name=name,
                        short_name=name,
                        owner_type=None,
                        symbol_kind=kind_name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        family="ts_js",
                        file_path=file_path,
                        visibility="public",
                        modifiers=frozenset({"export"}),
                        params=[],
                        norm_types=[],
                        req_count=0,
                        return_type=None,
                        signature_str=f"export {kw} {name}",
                        has_export=True,
                    ),
                )
            return

        if ntype in ("function_declaration", "generator_function_declaration"):
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, src_bytes).strip()
            if name and name not in _JS_SKIP_NAMES and not name.startswith("_"):
                is_exp = owner_exported or _has_export_ancestor(node)
                params_node = node.child_by_field_name("parameters")
                raw_p = _node_text(params_node, src_bytes).strip()
                if raw_p.startswith("(") and raw_p.endswith(")"):
                    raw_p = raw_p[1:-1]
                ret_node = node.child_by_field_name("return_type")
                ret_txt = normalize_whitespace(_node_text(ret_node, src_bytes)).lstrip(": ").strip() or None
                params, ntypes, req = _parse_params_from_raw(raw_p, "ts_js")
                is_async = any(ch.type == "async" or _node_text(ch, src_bytes) == "async" for ch in node.children[:3])
                mods = frozenset((["export"] if is_exp else []) + (["async"] if is_async else []))
                sig = f"{'export ' if is_exp else ''}{'async ' if is_async else ''}function {name}({normalize_whitespace(raw_p)})" + (
                    f": {ret_txt}" if ret_txt else ""
                )
                _store_symbol(
                    syms,
                    _make_symbol(
                        qualified_name=name,
                        short_name=name,
                        owner_type=None,
                        symbol_kind="function",
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        family="ts_js",
                        file_path=file_path,
                        visibility="public" if is_exp else "internal",
                        modifiers=mods,
                        params=params,
                        norm_types=ntypes,
                        req_count=req,
                        return_type=ret_txt,
                        signature_str=sig,
                        has_export=is_exp,
                    ),
                )
            return

        if ntype == "variable_declarator":
            val = node.child_by_field_name("value")
            if val is not None and val.type in ("arrow_function", "function_expression"):
                name = _node_text(node.child_by_field_name("name"), src_bytes).strip()
                if name and name not in _JS_SKIP_NAMES and not name.startswith("_"):
                    is_exp = owner_exported or _has_export_ancestor(node)
                    params_node = val.child_by_field_name("parameters")
                    if params_node is not None:
                        raw_p = _node_text(params_node, src_bytes).strip()
                        if raw_p.startswith("(") and raw_p.endswith(")"):
                            raw_p = raw_p[1:-1]
                    else:
                        single = val.child_by_field_name("parameter")
                        raw_p = _node_text(single, src_bytes).strip()
                    ret_node = val.child_by_field_name("return_type")
                    ret_txt = normalize_whitespace(_node_text(ret_node, src_bytes)).lstrip(": ").strip() or None
                    params, ntypes, req = _parse_params_from_raw(raw_p, "ts_js")
                    mods = frozenset({"export"}) if is_exp else frozenset()
                    sig = f"{'export ' if is_exp else ''}const {name} = ({normalize_whitespace(raw_p)})" + (
                        f": {ret_txt}" if ret_txt else ""
                    ) + " =>"
                    _store_symbol(
                        syms,
                        _make_symbol(
                            qualified_name=name,
                            short_name=name,
                            owner_type=None,
                            symbol_kind="function",
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                            family="ts_js",
                            file_path=file_path,
                            visibility="public" if is_exp else "internal",
                            modifiers=mods,
                            params=params,
                            norm_types=ntypes,
                            req_count=req,
                            return_type=ret_txt,
                            signature_str=sig,
                            has_export=is_exp,
                        ),
                    )
            return

        if ntype in ("method_definition", "method_signature", "public_field_definition"):
            if ntype == "public_field_definition":
                val = node.child_by_field_name("value")
                if val is None or val.type not in ("arrow_function", "function_expression"):
                    return
                fn_node = val
            else:
                fn_node = node
            name = _node_text(node.child_by_field_name("name"), src_bytes).strip()
            if not name or name in _JS_SKIP_NAMES or name.startswith(("_", "#")):
                return
            mods_list: list[str] = []
            vis = "public"
            for ch in node.children:
                if ch.type in ("accessibility_modifier", "override_modifier", "static", "async", "readonly"):
                    tok = _node_text(ch, src_bytes).strip().lower()
                    mods_list.append(tok)
                    if tok in ("private", "protected", "public"):
                        vis = tok
                elif _node_text(ch, src_bytes).strip() in ("async", "static", "get", "set"):
                    mods_list.append(_node_text(ch, src_bytes).strip())
            params_node = fn_node.child_by_field_name("parameters")
            raw_p = _node_text(params_node, src_bytes).strip()
            if raw_p.startswith("(") and raw_p.endswith(")"):
                raw_p = raw_p[1:-1]
            ret_node = fn_node.child_by_field_name("return_type")
            ret_txt = normalize_whitespace(_node_text(ret_node, src_bytes)).lstrip(": ").strip() or None
            params, ntypes, req = _parse_params_from_raw(raw_p, "ts_js")
            sig = f"{name}({normalize_whitespace(raw_p)})" + (f": {ret_txt}" if ret_txt else "")
            _store_symbol(
                syms,
                _make_symbol(
                    qualified_name=name,
                    short_name=name,
                    owner_type=owner,
                    symbol_kind="method",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    family="ts_js",
                    file_path=file_path,
                    visibility=vis if owner_exported else ("private" if vis == "private" else "internal"),
                    modifiers=frozenset(mods_list),
                    params=params,
                    norm_types=ntypes,
                    req_count=req,
                    return_type=ret_txt,
                    signature_str=sig,
                    has_export=owner_exported and vis != "private",
                ),
            )
            return

        for ch in node.children:
            if ch.is_named:
                _visit(ch, owner, owner_exported)

    _visit(root, None, False)


def _walk_go(root: Any, src_bytes: bytes, file_path: str, syms: dict[str, ParsedMultiLangSymbol]) -> None:
    def _extract_go_recv_type(recv_node: Any) -> str | None:
        if recv_node is None:
            return None
        for ch in recv_node.children:
            if ch.type == "parameter_declaration":
                tp = ch.child_by_field_name("type")
                if tp is not None:
                    txt = normalize_whitespace(_node_text(tp, src_bytes)).lstrip("*")
                    # Strip generic type params like `Client[T]`
                    bracket = txt.find("[")
                    if bracket != -1:
                        txt = txt[:bracket]
                    return txt.split(".")[-1].strip() or None
        return None

    for node in root.children:
        if not node.is_named:
            continue
        if node.type in ("function_declaration", "method_declaration"):
            name = _node_text(node.child_by_field_name("name"), src_bytes).strip()
            if not name:
                continue
            recv_node = node.child_by_field_name("receiver")
            recv_type = _extract_go_recv_type(recv_node)
            params_node = node.child_by_field_name("parameters")
            raw_p = _node_text(params_node, src_bytes).strip()
            if raw_p.startswith("(") and raw_p.endswith(")"):
                raw_p = raw_p[1:-1]
            res_node = node.child_by_field_name("result")
            ret_txt = normalize_whitespace(_node_text(res_node, src_bytes)) or None
            params, ntypes, req = _parse_params_from_raw(raw_p, "go")
            qname = f"{recv_type}.{name}" if recv_type else name
            recv_raw = normalize_whitespace(_node_text(recv_node, src_bytes)) if recv_node is not None else ""
            if recv_raw.startswith("(") and recv_raw.endswith(")"):
                recv_raw = recv_raw[1:-1].strip()
            sig = f"func {f'({recv_raw}) ' if recv_raw else ''}{name}({normalize_whitespace(raw_p)})" + (
                f" {ret_txt}" if ret_txt else ""
            )
            vis = "public" if name[:1].isupper() else "internal"
            _store_symbol(
                syms,
                _make_symbol(
                    qualified_name=qname,
                    short_name=name,
                    owner_type=recv_type,
                    symbol_kind="method" if recv_type else "function",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    family="go",
                    file_path=file_path,
                    visibility=vis,
                    modifiers=frozenset(),
                    params=params,
                    norm_types=ntypes,
                    req_count=req,
                    return_type=ret_txt,
                    signature_str=sig,
                ),
            )
        elif node.type == "type_declaration":
            for spec in node.children:
                if spec.type != "type_spec":
                    continue
                name = _node_text(spec.child_by_field_name("name"), src_bytes).strip()
                t_node = spec.child_by_field_name("type")
                if not name or t_node is None:
                    continue
                if t_node.type == "interface_type":
                    skind, kw = "interface", "interface"
                elif t_node.type == "struct_type":
                    skind, kw = "class", "struct"
                else:
                    continue
                vis = "public" if name[:1].isupper() else "internal"
                _store_symbol(
                    syms,
                    _make_symbol(
                        qualified_name=name,
                        short_name=name,
                        owner_type=None,
                        symbol_kind=skind,
                        start_line=spec.start_point[0] + 1,
                        end_line=spec.end_point[0] + 1,
                        family="go",
                        file_path=file_path,
                        visibility=vis,
                        modifiers=frozenset(),
                        params=[],
                        norm_types=[],
                        req_count=0,
                        return_type=None,
                        signature_str=f"type {name} {kw}",
                    ),
                )


def _walk_rust(root: Any, src_bytes: bytes, file_path: str, syms: dict[str, ParsedMultiLangSymbol]) -> None:
    def _rust_vis(node: Any) -> tuple[str, frozenset[str]]:
        mods: list[str] = []
        vis = "private"
        for ch in node.children:
            if ch.type == "visibility_modifier":
                txt = normalize_whitespace(_node_text(ch, src_bytes))
                mods.append(txt)
                vis = "public" if txt == "pub" else "internal"
            elif ch.type == "function_modifiers":
                for sub in normalize_whitespace(_node_text(ch, src_bytes)).split():
                    mods.append(sub)
        return vis, frozenset(mods)

    def _visit(node: Any, owner: str | None) -> None:
        ntype = node.type
        if ntype in ("struct_item", "enum_item", "trait_item"):
            name = _node_text(node.child_by_field_name("name"), src_bytes).strip()
            if name:
                vis, mods = _rust_vis(node)
                kind_map = {"struct_item": ("class", "struct"), "enum_item": ("enum", "enum"), "trait_item": ("interface", "trait")}
                skind, kw = kind_map[ntype]
                sig = f"{'pub ' if vis == 'public' else ''}{kw} {name}"
                _store_symbol(
                    syms,
                    _make_symbol(
                        qualified_name=name,
                        short_name=name,
                        owner_type=None,
                        symbol_kind=skind,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        family="rust",
                        file_path=file_path,
                        visibility=vis,
                        modifiers=mods,
                        params=[],
                        norm_types=[],
                        req_count=0,
                        return_type=None,
                        signature_str=sig,
                    ),
                )
            return

        if ntype == "impl_item":
            tp = node.child_by_field_name("type")
            impl_owner = normalize_whitespace(_node_text(tp, src_bytes)).split("<", 1)[0].split("::")[-1].strip() or None
            body = node.child_by_field_name("body")
            if body is not None:
                for ch in body.children:
                    _visit(ch, impl_owner)
            return

        if ntype in ("function_item", "function_signature_item"):
            name = _node_text(node.child_by_field_name("name"), src_bytes).strip()
            if name:
                vis, mods = _rust_vis(node)
                params_node = node.child_by_field_name("parameters")
                raw_p = _node_text(params_node, src_bytes).strip()
                if raw_p.startswith("(") and raw_p.endswith(")"):
                    raw_p = raw_p[1:-1]
                ret_node = node.child_by_field_name("return_type")
                ret_txt = normalize_whitespace(_node_text(ret_node, src_bytes)) or None
                params, ntypes, req = _parse_params_from_raw(raw_p, "rust")
                sig = f"{'pub ' if vis == 'public' else ''}fn {name}({normalize_whitespace(raw_p)})" + (
                    f" -> {ret_txt}" if ret_txt else ""
                )
                _store_symbol(
                    syms,
                    _make_symbol(
                        qualified_name=name,
                        short_name=name,
                        owner_type=owner,
                        symbol_kind="method" if owner else "function",
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        family="rust",
                        file_path=file_path,
                        visibility=vis,
                        modifiers=mods,
                        params=params,
                        norm_types=ntypes,
                        req_count=req,
                        return_type=ret_txt,
                        signature_str=sig,
                    ),
                    allow_overload=bool(owner),
                )
            return

        for ch in node.children:
            if ch.is_named:
                _visit(ch, owner)

    _visit(root, None)


def _walk_c_cpp(root: Any, src_bytes: bytes, file_path: str, syms: dict[str, ParsedMultiLangSymbol]) -> None:
    is_header = file_path.lower().endswith((".h", ".hh", ".hpp", ".hxx"))

    def _find_func_decl(node: Any) -> Any | None:
        curr = node
        while curr is not None:
            if curr.type == "function_declarator":
                return curr
            sub = curr.child_by_field_name("declarator")
            if sub is None:
                break
            curr = sub
        return None

    def _visit(node: Any, owner: str | None, cur_vis: str, in_anon_ns: bool) -> None:
        ntype = node.type
        if ntype == "namespace_definition":
            ns_name = node.child_by_field_name("name")
            ns_txt = normalize_whitespace(_node_text(ns_name, src_bytes)).lower() if ns_name is not None else ""
            anon = in_anon_ns or (ns_name is None) or any(tok in ns_txt for tok in ("internal", "detail", "impl"))
            body = node.child_by_field_name("body")
            if body is not None:
                for ch in body.children:
                    _visit(ch, owner, "internal" if anon else cur_vis, anon)
            return

        if ntype in ("class_specifier", "struct_specifier", "enum_specifier"):
            name_node = node.child_by_field_name("name")
            name = normalize_whitespace(_node_text(name_node, src_bytes))
            body = node.child_by_field_name("body")
            if name and body is not None and name not in _CPP_SKIP_NAMES and not (name.isupper() and len(name) >= 3):
                skind = "enum" if ntype == "enum_specifier" else "class"
                kw = "enum" if ntype == "enum_specifier" else ("struct" if ntype == "struct_specifier" else "class")
                vis = "internal" if in_anon_ns else "public"
                _store_symbol(
                    syms,
                    _make_symbol(
                        qualified_name=name,
                        short_name=name,
                        owner_type=None,
                        symbol_kind=skind,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        family="c_cpp",
                        file_path=file_path,
                        visibility=vis,
                        modifiers=frozenset(),
                        params=[],
                        norm_types=[],
                        req_count=0,
                        return_type=None,
                        signature_str=f"{kw} {name}",
                    ),
                )
                default_member_vis = "public" if ntype == "struct_specifier" else "private"
                active_vis = "internal" if in_anon_ns else default_member_vis
                if ntype != "enum_specifier":
                    for ch in body.children:
                        if ch.type == "access_specifier":
                            acc = normalize_whitespace(_node_text(ch, src_bytes)).rstrip(":").strip().lower()
                            if acc in ("public", "protected", "private"):
                                active_vis = "internal" if in_anon_ns else acc
                        elif ch.is_named:
                            _visit(ch, name, active_vis, in_anon_ns)
                return

        if ntype in ("template_declaration", "linkage_specification"):
            for ch in node.children:
                if ch.is_named and ch.type != "template_parameter_list":
                    _visit(ch, owner, cur_vis, in_anon_ns)
            return

        if ntype in ("function_definition", "field_declaration", "declaration"):
            if ntype == "declaration" and not is_header:
                # Forward declarations inside .cpp files shouldn't duplicate or shadow definitions.
                return
            top_decl = node.child_by_field_name("declarator")
            fdecl = _find_func_decl(top_decl)
            if fdecl is None:
                return
            ptr_suffix = ""
            curr_ptr = top_decl
            while curr_ptr is not None and curr_ptr.id != fdecl.id:
                if curr_ptr.type == "pointer_declarator":
                    ptr_suffix = "*" + ptr_suffix
                elif curr_ptr.type == "reference_declarator":
                    ptr_suffix = "&" + ptr_suffix
                curr_ptr = curr_ptr.child_by_field_name("declarator")
            inner_name_node = fdecl.child_by_field_name("declarator")
            raw_name = normalize_whitespace(_node_text(inner_name_node, src_bytes))
            if not raw_name:
                return
            short = raw_name.split("::")[-1].strip()
            if short in _CPP_SKIP_NAMES or short.startswith("~") or (short.isupper() and len(short) >= 3):
                return
            decl_owner = owner
            if "::" in raw_name:
                decl_owner = raw_name.rsplit("::", 1)[0].split("<", 1)[0].split("::")[-1].strip() or owner
                qname = raw_name
            elif owner:
                qname = f"{owner}::{short}"
            else:
                qname = short

            mods_list: list[str] = []
            for ch in node.children:
                if ch.type in ("storage_class_specifier", "type_qualifier", "virtual", "explicit", "friend"):
                    mods_list.append(normalize_whitespace(_node_text(ch, src_bytes)).lower())
            # Trailing qualifiers on function_declarator (const, override, final)
            for ch in fdecl.children:
                if ch.type in ("type_qualifier", "virtual_specifier"):
                    mods_list.append(normalize_whitespace(_node_text(ch, src_bytes)).lower())

            type_node = node.child_by_field_name("type")
            ret_txt = normalize_type_expr(_node_text(type_node, src_bytes) + ptr_suffix) if type_node is not None else None
            params_node = fdecl.child_by_field_name("parameters")
            raw_p = _node_text(params_node, src_bytes).strip()
            if raw_p.startswith("(") and raw_p.endswith(")"):
                raw_p = raw_p[1:-1]
            params, ntypes, req = _parse_params_from_raw(raw_p, "c_cpp")
            is_static = "static" in mods_list
            vis = "internal" if (in_anon_ns or is_static or cur_vis == "private") else cur_vis
            if owner is None and not is_static and not in_anon_ns:
                vis = "public"
            sig = f"{qname}({normalize_whitespace(raw_p)})"
            _store_symbol(
                syms,
                _make_symbol(
                    qualified_name=qname,
                    short_name=short,
                    owner_type=decl_owner,
                    symbol_kind="method" if decl_owner else "function",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    family="c_cpp",
                    file_path=file_path,
                    visibility=vis,
                    modifiers=frozenset(mods_list),
                    params=params,
                    norm_types=ntypes,
                    req_count=req,
                    return_type=ret_txt or None,
                    signature_str=sig,
                ),
                allow_overload=True,
            )
            return

        for ch in node.children:
            if ch.is_named:
                _visit(ch, owner, cur_vis, in_anon_ns)

    _visit(root, None, "public", False)


def _walk_csharp_java_kotlin_scala(
    root: Any,
    src_bytes: bytes,
    file_path: str,
    family: str,
    syms: dict[str, ParsedMultiLangSymbol],
) -> None:
    def _collect_mods(node: Any) -> frozenset[str]:
        mods: list[str] = []
        for ch in node.children:
            if ch.type in ("modifier", "modifiers", "visibility_modifier"):
                for tok in normalize_whitespace(_node_text(ch, src_bytes)).split():
                    mods.append(tok.lower())
        return frozenset(mods)

    default_vis = "public" if family in ("kotlin", "scala") else "internal"

    def _visit(node: Any, owner: str | None, owner_vis: str = "public") -> None:
        ntype = node.type
        if ntype in ("object_creation_expression", "object_literal"):
            return
        if ntype in (
            "class_declaration",
            "struct_declaration",
            "interface_declaration",
            "enum_declaration",
            "record_declaration",
            "object_declaration",
            "class_definition",
            "trait_definition",
            "object_definition",
        ):
            name_node = node.child_by_field_name("name")
            if name_node is None:
                for ch in node.children:
                    if ch.type in ("type_identifier", "simple_identifier", "identifier"):
                        name_node = ch
                        break
            name = _node_text(name_node, src_bytes).strip()
            if name:
                mods = _collect_mods(node)
                vis = resolve_visibility_from_modifiers(mods, default_visibility=default_vis)
                eff_vis = (
                    owner_vis
                    if (owner_vis in ("private", "internal") and vis in ("public", "protected"))
                    else vis
                )
                if "enum" in ntype or "enum" in mods:
                    skind, kw = "enum", "enum"
                elif "interface" in ntype or "trait" in ntype:
                    skind, kw = "interface", "interface" if "interface" in ntype else "trait"
                else:
                    skind, kw = "class", "class"
                _store_symbol(
                    syms,
                    _make_symbol(
                        qualified_name=name,
                        short_name=name,
                        owner_type=None,
                        symbol_kind=skind,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        family=family,
                        file_path=file_path,
                        visibility=eff_vis,
                        modifiers=mods,
                        params=[],
                        norm_types=[],
                        req_count=0,
                        return_type=None,
                        signature_str=f"{kw} {name}",
                    ),
                )
                body = node.child_by_field_name("body")
                if body is None:
                    for ch in node.children:
                        if ch.type in ("class_body", "declaration_list", "template_body", "enum_class_body"):
                            body = ch
                            break
                if body is not None:
                    for ch in body.children:
                        _visit(ch, name, eff_vis)
                return

        if ntype in ("method_declaration", "function_declaration", "function_definition"):
            name_node = node.child_by_field_name("name")
            if name_node is None:
                for ch in node.children:
                    if ch.type in ("simple_identifier", "identifier"):
                        name_node = ch
                        break
            name = _node_text(name_node, src_bytes).strip()
            if not name or name in _CPP_SKIP_NAMES:
                return
            mods = _collect_mods(node)
            vis = resolve_visibility_from_modifiers(mods, default_visibility=default_vis)
            eff_vis = (
                owner_vis
                if (owner_vis in ("private", "internal") and vis in ("public", "protected"))
                else vis
            )

            params_node = node.child_by_field_name("parameters")
            if params_node is None:
                for ch in node.children:
                    if ch.type in ("parameter_list", "formal_parameters", "function_value_parameters", "parameters"):
                        params_node = ch
                        break
            raw_p = _node_text(params_node, src_bytes).strip()
            if raw_p.startswith("(") and raw_p.endswith(")"):
                raw_p = raw_p[1:-1]
            params, ntypes, req = _parse_params_from_raw(raw_p, family)

            ret_node = (
                node.child_by_field_name("returns")
                or node.child_by_field_name("return_type")
                or node.child_by_field_name("type")
            )
            ret_txt: str | None = normalize_whitespace(_node_text(ret_node, src_bytes)) if ret_node is not None else None
            if not ret_txt and family == "kotlin" and params_node is not None:
                for ch in node.children:
                    if ch.start_byte > params_node.end_byte and ch.type in (
                        "user_type",
                        "nullable_type",
                        "function_type",
                        "type_identifier",
                    ):
                        ret_txt = normalize_whitespace(_node_text(ch, src_bytes))
                        break

            # Canonical modifier-order-insensitive signature formatting
            sorted_mods = " ".join(sorted(mods))
            prefix_mods = f"{sorted_mods} " if sorted_mods else ""
            ret_part = f"{ret_txt} " if ret_txt and family in ("csharp", "java") else ""
            ret_suffix = f": {ret_txt}" if ret_txt and family in ("kotlin", "scala") else ""
            sig = f"{prefix_mods}{ret_part}{name}({normalize_whitespace(raw_p)}){ret_suffix}".strip()

            _store_symbol(
                syms,
                _make_symbol(
                    qualified_name=name,
                    short_name=name,
                    owner_type=owner,
                    symbol_kind="method",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    family=family,
                    file_path=file_path,
                    visibility=eff_vis,
                    modifiers=mods,
                    params=params,
                    norm_types=ntypes,
                    req_count=req,
                    return_type=ret_txt or None,
                    signature_str=sig,
                ),
                allow_overload=True,
            )
            return

        for ch in node.children:
            if ch.is_named:
                _visit(ch, owner, owner_vis)

    _visit(root, None, "public")


def _walk_ruby_php_swift(
    root: Any,
    src_bytes: bytes,
    file_path: str,
    family: str,
    syms: dict[str, ParsedMultiLangSymbol],
) -> None:
    default_vis = "internal" if family == "swift" else "public"

    def _visit(node: Any, owner: str | None, member_vis: str) -> str:
        ntype = node.type
        if family == "ruby" and ntype == "identifier":
            tok = _node_text(node, src_bytes).strip()
            if tok in ("private", "protected", "public"):
                return tok
            return member_vis

        if ntype in (
            "class",
            "module",
            "class_declaration",
            "interface_declaration",
            "trait_declaration",
            "enum_declaration",
            "protocol_declaration",
            "struct_declaration",
        ):
            name_node = node.child_by_field_name("name")
            if name_node is None:
                for ch in node.children:
                    if ch.type in ("type_identifier", "constant", "name"):
                        name_node = ch
                        break
            name = _node_text(name_node, src_bytes).strip()
            if name:
                mods_list: list[str] = []
                for ch in node.children:
                    if ch.type in ("modifiers", "visibility_modifier", "abstract_modifier", "final_modifier"):
                        mods_list.extend(normalize_whitespace(_node_text(ch, src_bytes)).lower().split())
                mods = frozenset(mods_list)
                vis = resolve_visibility_from_modifiers(mods, default_visibility=default_vis)
                if "enum" in ntype:
                    skind, kw = "enum", "enum"
                elif any(x in ntype for x in ("interface", "trait", "protocol")):
                    skind, kw = "interface", ntype.split("_", 1)[0]
                else:
                    skind, kw = "class", "module" if ntype == "module" else "class"
                _store_symbol(
                    syms,
                    _make_symbol(
                        qualified_name=name,
                        short_name=name,
                        owner_type=None,
                        symbol_kind=skind,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        family=family,
                        file_path=file_path,
                        visibility=vis,
                        modifiers=mods,
                        params=[],
                        norm_types=[],
                        req_count=0,
                        return_type=None,
                        signature_str=f"{kw} {name}",
                    ),
                )
                body = node.child_by_field_name("body")
                if body is None:
                    for ch in node.children:
                        if ch.type in ("body_statement", "declaration_list", "class_body"):
                            body = ch
                            break
                if body is not None:
                    cur = "public"
                    for ch in body.children:
                        if ch.is_named:
                            cur = _visit(ch, name, cur)
                return member_vis

        if ntype in ("method", "singleton_method", "method_declaration", "function_definition", "function_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is None:
                for ch in node.children:
                    if ch.type in ("simple_identifier", "identifier", "name"):
                        name_node = ch
                        break
            name = _node_text(name_node, src_bytes).strip()
            if not name:
                return member_vis
            if family == "ruby" and ntype == "singleton_method":
                obj = _node_text(node.child_by_field_name("object"), src_bytes).strip()
                if obj == "self":
                    name = f"self.{name}"
            mods_list = []
            for ch in node.children:
                if ch.type == "attribute":
                    continue
                if family == "swift" and ch.type == "modifiers":
                    for m_ch in ch.children:
                        if m_ch.type == "attribute":
                            continue
                        for tok in normalize_whitespace(_node_text(m_ch, src_bytes)).lower().split():
                            if not tok.startswith("@") and tok in MODIFIER_TOKENS:
                                mods_list.append(tok)
                elif ch.type in ("modifiers", "visibility_modifier", "static_modifier", "abstract_modifier", "final_modifier"):
                    for tok in normalize_whitespace(_node_text(ch, src_bytes)).lower().split():
                        if family == "swift":
                            if not tok.startswith("@") and tok in MODIFIER_TOKENS:
                                mods_list.append(tok)
                        else:
                            mods_list.append(tok)
            mods = frozenset(mods_list)
            vis = (
                resolve_visibility_from_modifiers(mods, default_visibility=default_vis)
                if mods
                else (member_vis if family == "ruby" else default_vis)
            )
            params_node = node.child_by_field_name("parameters")
            if params_node is None:
                for ch in node.children:
                    if ch.type in ("method_parameters", "formal_parameters", "parameters"):
                        params_node = ch
                        break
            param_end_byte = node.start_byte
            if params_node is not None:
                raw_p = _node_text(params_node, src_bytes).strip()
                if raw_p.startswith("(") and raw_p.endswith(")"):
                    raw_p = raw_p[1:-1]
                param_end_byte = params_node.end_byte
            elif family == "swift":
                # Extract parameter list after `name_node` (skipping `@available(...)` attributes and `<...>` generics)
                start_off = name_node.end_byte if name_node is not None else node.start_byte
                after_txt = src_bytes[start_off : node.end_byte].decode("utf-8", errors="replace")
                raw_p = ""
                param_end_byte = start_off
                pos = 0
                n_txt = len(after_txt)
                while pos < n_txt and after_txt[pos].isspace():
                    pos += 1
                if pos < n_txt and after_txt[pos] == "<":
                    d_ang = 0
                    while pos < n_txt:
                        c_ch = after_txt[pos]
                        if c_ch == "<":
                            d_ang += 1
                        elif c_ch == ">":
                            if pos > 0 and after_txt[pos - 1] == "-":
                                pos += 1
                                continue
                            d_ang -= 1
                            if d_ang == 0:
                                pos += 1
                                break
                        pos += 1
                    while pos < n_txt and after_txt[pos].isspace():
                        pos += 1
                if pos < n_txt and after_txt[pos] == "(":
                    open_pos = pos
                    depth_p = 0
                    for i_ch in range(open_pos, n_txt):
                        if after_txt[i_ch] == "(":
                            depth_p += 1
                        elif after_txt[i_ch] == ")":
                            depth_p -= 1
                            if depth_p == 0:
                                raw_p = after_txt[open_pos + 1 : i_ch]
                                param_end_byte = start_off + len(
                                    after_txt[: i_ch + 1].encode("utf-8", errors="replace")
                                )
                                break
            else:
                raw_p = ""

            params, ntypes, req = _parse_params_from_raw(raw_p, family)
            ret_node = node.child_by_field_name("return_type")
            ret_txt = normalize_whitespace(_node_text(ret_node, src_bytes)) if ret_node is not None else None
            if not ret_txt and family == "swift":
                # In Swift CST, return type appears after parameter list and before function_body
                for ch in node.children:
                    if ch.start_byte >= param_end_byte and ch.type in (
                        "array_type",
                        "user_type",
                        "optional_type",
                        "tuple_type",
                        "dictionary_type",
                    ):
                        ret_txt = normalize_whitespace(_node_text(ch, src_bytes))
                        break
            sig = f"def {name}({normalize_whitespace(raw_p)})" + (f" -> {ret_txt}" if ret_txt else "")
            _store_symbol(
                syms,
                _make_symbol(
                    qualified_name=name,
                    short_name=name.split(".")[-1],
                    owner_type=owner,
                    symbol_kind="method" if owner else "function",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    family=family,
                    file_path=file_path,
                    visibility=vis,
                    modifiers=mods,
                    params=params,
                    norm_types=ntypes,
                    req_count=req,
                    return_type=ret_txt or None,
                    signature_str=sig,
                ),
                allow_overload=(family == "swift"),
            )
            return member_vis

        for ch in node.children:
            if ch.is_named:
                member_vis = _visit(ch, owner, member_vis)
        return member_vis

    _visit(root, None, default_vis)


def parse_multilang_symbols_treesitter(
    source: str,
    file_path: str,
) -> dict[str, ParsedMultiLangSymbol] | None:
    """Parse structural symbols across non-Python files using Tree-sitter.

    Returns ``None`` when Tree-sitter is disabled, unavailable, or unsupported
    for ``file_path`` so the caller can engage the fallback parser.
    """
    lang_name = get_treesitter_language_name(file_path)
    family = get_language_family(file_path)
    if not lang_name or not family:
        return None
    parse_src = _preprocess_cpp_export_macros(source) if lang_name in ("c", "cpp") else source
    tree, src_bytes = _parse_tree(parse_src, lang_name)
    if tree is None or src_bytes is None:
        return None

    syms: dict[str, ParsedMultiLangSymbol] = {}
    root = tree.root_node
    if family == "ts_js":
        _walk_ts_js(root, src_bytes, file_path, syms)
    elif family == "go":
        _walk_go(root, src_bytes, file_path, syms)
    elif family == "rust":
        _walk_rust(root, src_bytes, file_path, syms)
    elif family == "c_cpp":
        _walk_c_cpp(root, src_bytes, file_path, syms)
    elif family in ("csharp", "java", "kotlin", "scala"):
        _walk_csharp_java_kotlin_scala(root, src_bytes, file_path, family, syms)
    elif family in ("ruby", "php", "swift"):
        _walk_ruby_php_swift(root, src_bytes, file_path, family, syms)
    else:
        return None

    return syms


_CALL_NODE_TYPES = frozenset(
    {
        "call_expression",
        "invocation_expression",
        "method_invocation",
        "member_call_expression",
        "function_call_expression",
        "scoped_call_expression",
        "call",
        "new_expression",
        "object_creation_expression",
    }
)


def _extract_receiver_and_callee(call_node: Any, src_bytes: bytes) -> tuple[str | None, str | None]:
    """Extract (callee_short_name, immediate_receiver) from a Tree-sitter call node."""
    ntype = call_node.type

    if ntype == "method_invocation":
        name_n = call_node.child_by_field_name("name")
        obj_n = call_node.child_by_field_name("object")
        callee = normalize_whitespace(_node_text(name_n, src_bytes)) if name_n else None
        recv = _last_ident_from_expr(_node_text(obj_n, src_bytes)) if obj_n else None
        return callee, recv

    if ntype == "member_call_expression":
        name_n = call_node.child_by_field_name("name")
        obj_n = call_node.child_by_field_name("object")
        callee = normalize_whitespace(_node_text(name_n, src_bytes)) if name_n else None
        recv = _last_ident_from_expr(_node_text(obj_n, src_bytes)) if obj_n else None
        return callee, recv

    if ntype == "call":
        meth_n = call_node.child_by_field_name("method") or call_node.child_by_field_name("function")
        recv_n = call_node.child_by_field_name("receiver")
        callee = normalize_whitespace(_node_text(meth_n, src_bytes)) if meth_n else None
        recv = _last_ident_from_expr(_node_text(recv_n, src_bytes)) if recv_n else None
        return callee, recv

    if ntype in ("object_creation_expression", "new_expression"):
        tp_n = call_node.child_by_field_name("type") or call_node.child_by_field_name("constructor")
        txt = normalize_whitespace(_node_text(tp_n, src_bytes)) if tp_n else ""
        return _last_ident_from_expr(txt), None

    # Generic `call_expression` / `invocation_expression` / `function_call_expression` / `scoped_call_expression`
    fn_n = (
        call_node.child_by_field_name("function")
        or call_node.child_by_field_name("name")
        or call_node.child_by_field_name("scope")
    )
    if fn_n is None:
        # Swift / Kotlin `call_expression` stores callee in first child
        for ch in call_node.children:
            if ch.is_named and ch.type not in ("call_suffix", "value_arguments", "argument_list", "arguments"):
                fn_n = ch
                break
    if fn_n is None:
        return None, None

    fn_txt = normalize_whitespace(_node_text(fn_n, src_bytes))
    if not fn_txt:
        return None, None
    # Split off template/generic suffixes like `Foo<T>` -> `Foo`
    fn_no_gen = re.sub(r"<[^>]*>$", "", fn_txt).strip()
    for sep in ("::", "->", ".", "\\"):
        if sep in fn_no_gen:
            lhs, rhs = fn_no_gen.rsplit(sep, 1)
            return _last_ident_from_expr(rhs), _last_ident_from_expr(lhs)
    return _last_ident_from_expr(fn_no_gen), None


def _last_ident_from_expr(expr_text: str) -> str | None:
    if not expr_text:
        return None
    clean = re.sub(r"\([^)]*\)$", "", expr_text.strip())
    m = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", clean)
    return m[-1] if m else None


def extract_multilang_calls_treesitter(
    source: str,
    file_path: str,
    target_short_names: set[str],
) -> list[ParsedCallSite] | None:
    """Extract genuine call invocations matching ``target_short_names`` via Tree-sitter.

    Comments, string literals, and declaration signatures are inherently skipped.
    Returns ``None`` if Tree-sitter is unavailable/disabled so fallback can run.
    """
    if not target_short_names:
        return []
    # Fast text gate avoids constructing a CST on unrelated repository files.
    if not any(name in source for name in target_short_names):
        return []

    lang_name = get_treesitter_language_name(file_path)
    if not lang_name:
        return None
    tree, src_bytes = _parse_tree(source, lang_name)
    if tree is None or src_bytes is None:
        return None

    lines = source.splitlines()
    calls: list[ParsedCallSite] = []
    stack: list[Any] = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("ERROR", "function_declarator"):
            continue
        if node.type in _CALL_NODE_TYPES:
            callee, recv = _extract_receiver_and_callee(node, src_bytes)
            if callee and not callee.startswith("~") and callee in target_short_names:
                lineno = node.start_point[0] + 1
                args_n = node.child_by_field_name("arguments")
                arg_cnt: int | None = None
                if args_n is not None:
                    arg_txt = _node_text(args_n, src_bytes).strip()
                    if arg_txt.startswith("(") and arg_txt.endswith(")"):
                        inner = arg_txt[1:-1].strip()
                        arg_cnt = len(split_top_level_comma(inner)) if inner else 0
                snippet = lines[lineno - 1].strip()[:160] if 1 <= lineno <= len(lines) else normalize_whitespace(_node_text(node, src_bytes))[:160]
                if not snippet.startswith("~"):
                    calls.append(
                        ParsedCallSite(
                            callee_name=callee,
                            receiver=recv,
                            line_number=lineno,
                            arg_count=arg_cnt,
                            call_snippet=snippet,
                        )
                    )
        for ch in reversed(node.children):
            if ch.is_named:
                stack.append(ch)

    calls.sort(key=lambda c: (c.line_number, c.callee_name))
    return calls
