"""Persistent, Incremental Code Knowledge Graph Builder & Snapshot Store.

Distills `graphify`'s zero-LLM AST graph + deterministic community clustering
with `rea`'s `ev_<sha256>` / `unk_<sha256>` epistemic provenance, atomic snapshot
swaps (preventing event-loop blocking), and default test/utility down-weighting.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from athena._fast_kernels import (
    _IMPORT_PATTERNS,
    _PHP_DYNAMIC_RE,
    _STRUCTURAL_PATTERNS,
    _TS_JS_REEXPORT_RE,
    compute_community_assignments,
    extract_structural_symbols_raw,
)
from athena.evidence_store import (
    CompletenessStatus,
    EvidenceConfidence,
    ResidualUnknownRecord,
    canonical_evidence_id,
    canonical_unknown_id,
    resolve_completeness,
)
from athena.git_inspector import (
    IGNORED_DIR_PREFIXES,
    LOCKFILE_AND_GENERATED_NAMES,
    MAX_SOURCE_BLOB_BYTES,
    run_git_command,
)
from athena.security import is_safe_repo_file, redact_secrets, validate_repo_path

_GRAPH_SCHEMA_VERSION = 1

_TEST_PATH_MARKERS = ("tests/", "test/", "__tests__/", "spec/", "specs/")
_TEST_FILE_PREFIXES = ("test_", "spec_")
_TEST_FILE_SUFFIXES = ("_test.py", ".test.ts", ".test.tsx", ".test.js", ".spec.ts", ".spec.js", "_test.go", "_test.rs")
_UTILITY_NAMES = frozenset({"cn", "clsx", "noop", "identity", "main", "setup", "teardown", "__init__", "__repr__", "__str__"})

_LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".cu": "cuda",
    ".cuh": "cuda",
    ".tex": "tex",
}

_LANG_FAMILY: dict[str, str] = {
    "python": "python",
    "typescript": "jsts",
    "javascript": "jsts",
    "go": "go",
    "rust": "rust",
    "java": "jvm",
    "kotlin": "jvm",
    "ruby": "ruby",
    "php": "php",
    "csharp": "dotnet",
    "c": "c_cpp",
    "cpp": "c_cpp",
    "cuda": "c_cpp",
    "tex": "tex",
}


class GraphNode(BaseModel):
    """A symbol or file entity in the persistent Athena code knowledge graph."""

    id: str
    label: str
    kind: Literal["module", "class", "function", "method", "interface", "struct", "type"]
    language: str
    file_path: str
    line: int = 1
    community: int = 0
    is_test_or_utility: bool = False
    confidence: EvidenceConfidence = "observed"
    evidence_id: str = ""


class GraphEdge(BaseModel):
    """A directed relationship between two graph nodes with explicit provenance."""

    source: str
    target: str
    relation: Literal["contains", "imports", "calls", "inherits"]
    confidence: EvidenceConfidence = "observed"
    weight: float = 1.0
    evidence_id: str = ""


class CodeGraph(BaseModel):
    """Serializable persistent codebase knowledge graph."""

    schema_version: int = _GRAPH_SCHEMA_VERSION
    repo_root: str
    graph_evidence_id: str
    completeness: CompletenessStatus = "unknown"
    total_files_scanned: int = 0
    skipped_files: int = 0
    parse_errors: int = 0
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    community_labels: dict[str, str] = Field(default_factory=dict)
    unknowns: list[ResidualUnknownRecord] = Field(default_factory=list)


def _is_test_or_utility_path(rel_path: str, symbol: str = "") -> bool:
    norm = rel_path.replace("\\", "/").lower()
    base = Path(norm).name
    if any(marker in norm for marker in _TEST_PATH_MARKERS):
        return True
    if base.startswith(_TEST_FILE_PREFIXES) or base.endswith(_TEST_FILE_SUFFIXES):
        return True
    if symbol and (symbol.lower() in _UTILITY_NAMES or symbol.startswith("_make_")):
        return True
    return False


def _should_skip_rel_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").lstrip("./")
    if not norm or norm.startswith(".athena/") or norm.startswith(".fast/") or norm.startswith("private/"):
        return True
    if Path(norm).name in LOCKFILE_AND_GENERATED_NAMES:
        return True
    return any(norm.startswith(prefix) for prefix in IGNORED_DIR_PREFIXES)


def _collect_tracked_source_files(repo_root: Path) -> list[Path]:
    """Enumerate safe repository source files via `git ls-files` with fallback walk."""
    files: list[Path] = []
    try:
        proc = run_git_command(repo_root, ["ls-files", "-z"], timeout=10)
        if proc.returncode == 0 and proc.stdout:
            for raw in proc.stdout.split("\0"):
                if not raw:
                    continue
                if _should_skip_rel_path(raw):
                    continue
                candidate = repo_root / raw
                if candidate.suffix.lower() not in _LANG_BY_EXT:
                    continue
                if is_safe_repo_file(repo_root, candidate):
                    files.append(candidate)
            return sorted(files)
    except Exception:
        pass

    for root_dir, dirnames, filenames in os.walk(repo_root, followlinks=False):
        rel_dir = Path(root_dir).relative_to(repo_root).as_posix()
        dirnames[:] = sorted(
            d
            for d in dirnames
            if not d.startswith(".")
            and d not in {"node_modules", "__pycache__", "venv", ".venv", "dist", "build", "target", "private"}
        )
        for name in sorted(filenames):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            if _should_skip_rel_path(rel):
                continue
            candidate = Path(root_dir) / name
            if candidate.suffix.lower() not in _LANG_BY_EXT:
                continue
            if is_safe_repo_file(repo_root, candidate):
                files.append(candidate)
    return files


def _extract_python_file_graph(
    rel_path: str,
    source: str,
) -> tuple[list[GraphNode], list[GraphEdge], list[dict[str, Any]], list[ResidualUnknownRecord], int]:
    """Extract AST nodes, edges, unresolved call hints, and dynamic unknowns for a Python file."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    call_hints: list[dict[str, Any]] = []
    unknowns: list[ResidualUnknownRecord] = []

    mod_id = f"mod:{rel_path}"
    mod_is_test = _is_test_or_utility_path(rel_path)
    nodes.append(
        GraphNode(
            id=mod_id,
            label=Path(rel_path).stem,
            kind="module",
            language="python",
            file_path=rel_path,
            line=1,
            is_test_or_utility=mod_is_test,
            confidence="observed",
            evidence_id=canonical_evidence_id({"file": rel_path, "kind": "module"}),
        )
    )

    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        unk_payload = {"kind": "parser_partial", "file": rel_path, "line": exc.lineno or 0}
        unknowns.append(
            ResidualUnknownRecord(
                unknown_id=canonical_unknown_id(unk_payload),
                kind="parser_partial",
                severity="medium",
                file_path=rel_path,
                line=exc.lineno or 0,
                detail=f"Python SyntaxError: {redact_secrets(str(exc.msg or exc))}",
                remediation="Fix syntax error or target a valid Python >=3.12 file.",
            )
        )
        return nodes, edges, call_hints, unknowns, 1

    defined_locals: dict[str, str] = {}

    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                call_hints.append({"source": mod_id, "target_name": alias.name, "relation": "imports", "lang": "python"})
        elif isinstance(stmt, ast.ImportFrom) and stmt.module:
            call_hints.append({"source": mod_id, "target_name": stmt.module, "relation": "imports", "lang": "python"})
        elif isinstance(stmt, ast.ClassDef):
            cls_id = f"sym:{rel_path}::{stmt.name}"
            defined_locals[stmt.name] = cls_id
            nodes.append(
                GraphNode(
                    id=cls_id,
                    label=stmt.name,
                    kind="class",
                    language="python",
                    file_path=rel_path,
                    line=stmt.lineno,
                    is_test_or_utility=mod_is_test or _is_test_or_utility_path(rel_path, stmt.name),
                    confidence="observed",
                    evidence_id=canonical_evidence_id({"id": cls_id, "line": stmt.lineno}),
                )
            )
            edges.append(
                GraphEdge(
                    source=mod_id,
                    target=cls_id,
                    relation="contains",
                    confidence="observed",
                    evidence_id=canonical_evidence_id({"src": mod_id, "tgt": cls_id, "rel": "contains"}),
                )
            )
            for kw in stmt.keywords:
                if kw.arg == "metaclass":
                    unk_payload = {"kind": "dynamic_dispatch", "file": rel_path, "line": stmt.lineno, "sym": f"{stmt.name}:metaclass"}
                    unknowns.append(
                        ResidualUnknownRecord(
                            unknown_id=canonical_unknown_id(unk_payload),
                            kind="dynamic_dispatch",
                            severity="medium",
                            file_path=rel_path,
                            line=stmt.lineno,
                            symbol=cls_id,
                            detail=f"Class `{stmt.name}` uses a custom metaclass; synthesized attributes are not statically resolved.",
                            remediation="Inspect metaclass definition for runtime-injected methods or fields.",
                        )
                    )
            for base in stmt.bases:
                base_name = ast.unparse(base) if hasattr(ast, "unparse") else getattr(base, "id", "")
                if base_name:
                    call_hints.append({"source": cls_id, "target_name": base_name.split(".")[-1], "relation": "inherits", "lang": "python"})
            for child in stmt.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if child.name == "__init_subclass__":
                        unk_payload = {"kind": "dynamic_dispatch", "file": rel_path, "line": child.lineno, "sym": f"{stmt.name}.__init_subclass__"}
                        unknowns.append(
                            ResidualUnknownRecord(
                                unknown_id=canonical_unknown_id(unk_payload),
                                kind="dynamic_dispatch",
                                severity="medium",
                                file_path=rel_path,
                                line=child.lineno,
                                symbol=cls_id,
                                detail=f"Class `{stmt.name}` defines `__init_subclass__`; subclass hooks may mutate attributes at runtime.",
                                remediation="Inspect `__init_subclass__` for runtime-injected attributes.",
                            )
                        )
                    meth_id = f"sym:{rel_path}::{stmt.name}.{child.name}"
                    defined_locals[child.name] = meth_id
                    nodes.append(
                        GraphNode(
                            id=meth_id,
                            label=f"{stmt.name}.{child.name}",
                            kind="method",
                            language="python",
                            file_path=rel_path,
                            line=child.lineno,
                            is_test_or_utility=mod_is_test or _is_test_or_utility_path(rel_path, child.name),
                            confidence="observed",
                            evidence_id=canonical_evidence_id({"id": meth_id, "line": child.lineno}),
                        )
                    )
                    edges.append(
                        GraphEdge(
                            source=cls_id,
                            target=meth_id,
                            relation="contains",
                            confidence="observed",
                            evidence_id=canonical_evidence_id({"src": cls_id, "tgt": meth_id, "rel": "contains"}),
                        )
                    )
                    _collect_python_calls(child, meth_id, call_hints, unknowns, rel_path)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_id = f"sym:{rel_path}::{stmt.name}"
            defined_locals[stmt.name] = fn_id
            nodes.append(
                GraphNode(
                    id=fn_id,
                    label=stmt.name,
                    kind="function",
                    language="python",
                    file_path=rel_path,
                    line=stmt.lineno,
                    is_test_or_utility=mod_is_test or _is_test_or_utility_path(rel_path, stmt.name),
                    confidence="observed",
                    evidence_id=canonical_evidence_id({"id": fn_id, "line": stmt.lineno}),
                )
            )
            edges.append(
                GraphEdge(
                    source=mod_id,
                    target=fn_id,
                    relation="contains",
                    confidence="observed",
                    evidence_id=canonical_evidence_id({"src": mod_id, "tgt": fn_id, "rel": "contains"}),
                )
            )
            _collect_python_calls(stmt, fn_id, call_hints, unknowns, rel_path)

    # Resolve same-file direct calls immediately with `derived` confidence
    remaining_hints: list[dict[str, Any]] = []
    for hint in call_hints:
        if hint["relation"] == "calls" and hint["target_name"] in defined_locals:
            tgt_id = defined_locals[hint["target_name"]]
            if tgt_id != hint["source"]:
                edges.append(
                    GraphEdge(
                        source=hint["source"],
                        target=tgt_id,
                        relation="calls",
                        confidence="derived",
                        evidence_id=canonical_evidence_id({"src": hint["source"], "tgt": tgt_id, "rel": "calls"}),
                    )
                )
        else:
            remaining_hints.append(hint)

    return nodes, edges, remaining_hints, unknowns, 0


def _collect_python_calls(
    func_node: ast.AST,
    caller_id: str,
    call_hints: list[dict[str, Any]],
    unknowns: list[ResidualUnknownRecord],
    rel_path: str,
) -> None:
    """Walk a Python function body to extract static call hints and dynamic dispatch unknowns."""
    seen_calls: set[str] = set()
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        name = ""
        if isinstance(callee, ast.Name):
            name = callee.id
        elif isinstance(callee, ast.Attribute):
            name = callee.attr

        if name in {"getattr", "setattr", "delattr", "eval", "exec", "import_module", "__import__", "globals", "locals"}:
            unk_payload = {"kind": "dynamic_dispatch", "file": rel_path, "line": getattr(node, "lineno", 0), "sym": name}
            unknowns.append(
                ResidualUnknownRecord(
                    unknown_id=canonical_unknown_id(unk_payload),
                    kind="dynamic_dispatch",
                    severity="medium",
                    file_path=rel_path,
                    line=getattr(node, "lineno", 0),
                    symbol=caller_id,
                    detail=f"Dynamic dispatch via `{name}(...)` cannot be statically resolved.",
                    remediation="Verify callers manually or annotate explicit dispatch targets.",
                )
            )
        elif name and name not in seen_calls:
            seen_calls.add(name)
            call_hints.append({"source": caller_id, "target_name": name, "relation": "calls", "lang": "python"})


def _extract_structural_file_graph(
    rel_path: str,
    language: str,
    source: str,
) -> tuple[list[GraphNode], list[GraphEdge], list[dict[str, Any]], list[ResidualUnknownRecord], int]:
    """Extract symbols and import hints for non-Python files using bounded line-anchored regexes."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    call_hints: list[dict[str, Any]] = []
    mod_id = f"mod:{rel_path}"
    mod_is_test = _is_test_or_utility_path(rel_path)

    nodes.append(
        GraphNode(
            id=mod_id,
            label=Path(rel_path).stem,
            kind="module",
            language=language,
            file_path=rel_path,
            line=1,
            is_test_or_utility=mod_is_test,
            confidence="observed",
            evidence_id=canonical_evidence_id({"file": rel_path, "kind": "module"}),
        )
    )

    seen_syms: set[str] = set()
    unknowns: list[ResidualUnknownRecord] = []

    raw_symbols, import_targets, php_dynamic_lines = extract_structural_symbols_raw(language, source)

    for imp_tgt in import_targets:
        call_hints.append({"source": mod_id, "target_name": imp_tgt, "relation": "imports", "lang": language})

    for idx in php_dynamic_lines:
        unk_payload = {"kind": "dynamic_dispatch", "file": rel_path, "line": idx, "sym": "php_dynamic"}
        unknowns.append(
            ResidualUnknownRecord(
                unknown_id=canonical_unknown_id(unk_payload),
                kind="dynamic_dispatch",
                severity="medium",
                file_path=rel_path,
                line=idx,
                symbol=mod_id,
                detail="Dynamic PHP/Laravel magic or container binding (`__callStatic`/`__call`/`bind`/`make`) cannot be statically resolved.",
                remediation="Inspect service provider bindings or facade target manually.",
            )
        )

    for sym, idx in raw_symbols:
        sym_id = f"sym:{rel_path}::{sym}" if sym not in seen_syms else f"sym:{rel_path}::{sym}@L{idx}"
        seen_syms.add(sym)
        nodes.append(
            GraphNode(
                id=sym_id,
                label=sym,
                kind="function",
                language=language,
                file_path=rel_path,
                line=idx,
                is_test_or_utility=mod_is_test or _is_test_or_utility_path(rel_path, sym),
                confidence="observed",
                evidence_id=canonical_evidence_id({"id": sym_id, "line": idx}),
            )
        )
        edges.append(
            GraphEdge(
                source=mod_id,
                target=sym_id,
                relation="contains",
                confidence="observed",
                evidence_id=canonical_evidence_id({"src": mod_id, "tgt": sym_id, "rel": "contains"}),
            )
        )

    return nodes, edges, call_hints, unknowns, 0


def _assign_deterministic_communities(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
) -> dict[str, str]:
    """Deterministic label-propagation community clustering independent of PYTHONHASHSEED."""
    if not nodes:
        return {}

    final_comm, community_labels = compute_community_assignments(
        [n.id for n in nodes],
        [n.is_test_or_utility for n in nodes],
        [n.label for n in nodes],
        [(e.source, e.target, e.relation, e.weight, e.confidence) for e in edges],
    )
    for node in nodes:
        node.community = final_comm.get(node.id, 0)
    return community_labels


def _atomic_write_json(target: Path, data: dict[str, Any]) -> None:
    """Write JSON atomically via temp file + os.replace to prevent partial/corrupt graphs."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, target)


def build_code_graph(
    repo_path: str | Path,
    *,
    persist: bool = True,
    use_cache: bool = True,
) -> CodeGraph:
    """Build (or incrementally update) the persistent Athena code knowledge graph."""
    repo_root = validate_repo_path(repo_path)
    cache_path = repo_root / ".athena" / "graph_cache.json"
    graph_path = repo_root / ".athena" / "graph.json"

    prev_cache: dict[str, Any] = {}
    if use_cache and cache_path.is_file():
        try:
            loaded = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and loaded.get("schema_version") == _GRAPH_SCHEMA_VERSION:
                prev_cache = loaded.get("files", {})
        except Exception:
            prev_cache = {}

    source_files = _collect_tracked_source_files(repo_root)
    new_cache: dict[str, Any] = {}
    all_nodes: list[GraphNode] = []
    all_edges: list[GraphEdge] = []
    all_hints: list[dict[str, Any]] = []
    all_unknowns: list[ResidualUnknownRecord] = []
    skipped_files = 0
    parse_errors = 0

    for file_path in source_files:
        rel_path = file_path.relative_to(repo_root).as_posix()
        lang = _LANG_BY_EXT.get(file_path.suffix.lower(), "unknown")
        try:
            raw_bytes = file_path.read_bytes()
        except OSError:
            skipped_files += 1
            continue

        if len(raw_bytes) > MAX_SOURCE_BLOB_BYTES:
            skipped_files += 1
            all_unknowns.append(
                ResidualUnknownRecord(
                    unknown_id=canonical_unknown_id({"kind": "binary_or_oversized", "file": rel_path}),
                    kind="binary_or_oversized",
                    severity="low",
                    file_path=rel_path,
                    detail=f"File exceeds {MAX_SOURCE_BLOB_BYTES} byte cap.",
                    remediation="Inspect manually if this file defines core public APIs.",
                )
            )
            continue

        file_hash = hashlib.sha256(raw_bytes).hexdigest()
        cached_entry = prev_cache.get(rel_path) if use_cache else None
        if isinstance(cached_entry, dict) and cached_entry.get("sha256") == file_hash:
            nodes = [GraphNode.model_validate(n) for n in cached_entry.get("nodes", [])]
            edges = [GraphEdge.model_validate(e) for e in cached_entry.get("edges", [])]
            hints = list(cached_entry.get("hints", []))
            unknowns = [ResidualUnknownRecord.model_validate(u) for u in cached_entry.get("unknowns", [])]
            p_err = int(cached_entry.get("parse_errors", 0))
        else:
            text = raw_bytes.decode("utf-8", errors="replace").lstrip("\ufeff")
            if lang == "python":
                nodes, edges, hints, unknowns, p_err = _extract_python_file_graph(rel_path, text)
            else:
                nodes, edges, hints, unknowns, p_err = _extract_structural_file_graph(rel_path, lang, text)

        new_cache[rel_path] = {
            "sha256": file_hash,
            "nodes": [n.model_dump(mode="json") for n in nodes],
            "edges": [e.model_dump(mode="json") for e in edges],
            "hints": hints,
            "unknowns": [u.model_dump(mode="json") for u in unknowns],
            "parse_errors": p_err,
        }
        all_nodes.extend(nodes)
        all_edges.extend(edges)
        all_hints.extend(hints)
        all_unknowns.extend(unknowns)
        parse_errors += p_err

    # Cross-file resolution scoped strictly within same language family (prevents false cross-lang edges)
    symbols_by_family_and_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    modules_by_stem: dict[str, list[str]] = defaultdict(list)
    for n in all_nodes:
        fam = _LANG_FAMILY.get(n.language, n.language)
        if n.kind == "module":
            stem = Path(n.file_path).with_suffix("").as_posix().replace("/", ".")
            modules_by_stem[stem].append(n.id)
            modules_by_stem[Path(n.file_path).stem].append(n.id)
            if Path(n.file_path).stem == "index" and Path(n.file_path).parent.as_posix() != ".":
                pkg_stem = Path(n.file_path).parent.as_posix().replace("/", ".")
                modules_by_stem[pkg_stem].append(n.id)
                modules_by_stem[Path(n.file_path).parent.name].append(n.id)
        else:
            short = n.label.split(".")[-1]
            symbols_by_family_and_name[(fam, short)].append(n.id)

    seen_edges = {(e.source, e.target, e.relation) for e in all_edges}
    for hint in all_hints:
        rel = hint["relation"]
        fam = _LANG_FAMILY.get(hint.get("lang", ""), hint.get("lang", ""))
        tgt_name = hint["target_name"]
        candidates: list[str] = []
        conf: EvidenceConfidence = "inferred"

        if rel == "imports":
            norm_mod = tgt_name.lstrip("./").replace("/", ".")
            candidates = modules_by_stem.get(norm_mod, []) or modules_by_stem.get(norm_mod.split(".")[-1], [])
            conf = "derived" if len(candidates) == 1 else "inferred"
        else:
            candidates = symbols_by_family_and_name.get((fam, tgt_name), [])
            conf = "inferred"

        # Cap ambiguous fan-out at 3 targets to avoid noisy hub explosion
        for tgt_id in candidates[:3]:
            key = (hint["source"], tgt_id, rel)
            if tgt_id != hint["source"] and key not in seen_edges:
                seen_edges.add(key)
                all_edges.append(
                    GraphEdge(
                        source=hint["source"],
                        target=tgt_id,
                        relation=rel,
                        confidence=conf,
                        evidence_id=canonical_evidence_id({"src": hint["source"], "tgt": tgt_id, "rel": rel}),
                    )
                )

    community_labels = _assign_deterministic_communities(all_nodes, all_edges)
    completeness = resolve_completeness(
        skipped_files=skipped_files,
        unresolved_unknowns=len(all_unknowns),
        parse_errors=parse_errors,
    )
    graph_ev_id = canonical_evidence_id(
        {
            "nodes": [n.id for n in all_nodes],
            "edges": [(e.source, e.target, e.relation) for e in all_edges],
        }
    )

    graph = CodeGraph(
        repo_root=str(repo_root),
        graph_evidence_id=graph_ev_id,
        completeness=completeness,
        total_files_scanned=len(source_files),
        skipped_files=skipped_files,
        parse_errors=parse_errors,
        nodes=all_nodes,
        edges=all_edges,
        community_labels=community_labels,
        unknowns=all_unknowns,
    )

    if persist:
        _atomic_write_json(cache_path, {"schema_version": _GRAPH_SCHEMA_VERSION, "files": new_cache})
        _atomic_write_json(graph_path, graph.model_dump(mode="json"))

    return graph


def load_code_graph(repo_path: str | Path) -> CodeGraph | None:
    """Load an existing `.athena/graph.json` if present and valid."""
    repo_root = validate_repo_path(repo_path)
    graph_path = repo_root / ".athena" / "graph.json"
    if not graph_path.is_file():
        return None
    try:
        data = json.loads(graph_path.read_text(encoding="utf-8"))
        return CodeGraph.model_validate(data)
    except Exception:
        return None


class GraphSnapshotManager:
    """Non-blocking atomic snapshot cache so MCP queries never block on disk/rebuild."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshots: dict[str, tuple[CodeGraph, int]] = {}

    def get_or_build(self, repo_path: str | Path, *, rebuild: bool = False) -> CodeGraph:
        """Return cached snapshot atomically, reloading if disk graph.json changed."""
        repo_root = validate_repo_path(repo_path)
        repo_key = str(repo_root)
        graph_file = repo_root / ".athena" / "graph.json"
        disk_mtime = graph_file.stat().st_mtime_ns if graph_file.is_file() else 0

        if not rebuild:
            with self._lock:
                entry = self._snapshots.get(repo_key)
            if entry is not None and entry[1] == disk_mtime and disk_mtime > 0:
                return entry[0]
            if disk_mtime > 0:
                disk_snap = load_code_graph(repo_root)
                if disk_snap is not None:
                    with self._lock:
                        self._snapshots[repo_key] = (disk_snap, disk_mtime)
                    return disk_snap

        fresh = build_code_graph(repo_root, persist=True, use_cache=True)
        fresh_mtime = graph_file.stat().st_mtime_ns if graph_file.is_file() else 0
        with self._lock:
            self._snapshots[repo_key] = (fresh, fresh_mtime)
        return fresh


DEFAULT_GRAPH_MANAGER = GraphSnapshotManager()
