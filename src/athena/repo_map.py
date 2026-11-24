"""Zero-Search Codebase Map Generator (`athena map`).

Builds compact, prompt-injection-safe folder export maps from Athena's
AST/structural graph with strict character budgets.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from athena.graph_store import DEFAULT_GRAPH_MANAGER, CodeGraph
from athena.security import AthenaValidationError

_SHARED_FOLDER_PRIORITY = (
    "core",
    "lib",
    "utils",
    "util",
    "helpers",
    "helper",
    "common",
    "shared",
    "services",
    "service",
    "models",
    "model",
    "schemas",
    "schema",
    "api",
    "src",
)

_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_.\-/]+$")
_SAFE_IDENT_RE = re.compile(r"^[A-Za-z0-9_.$]+$")


def _sanitize_token(raw: str, pattern: re.Pattern[str]) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.\-/]", "_", raw)
    return cleaned if pattern.match(cleaned) else ""


def _folder_priority(folder: str) -> tuple[int, str]:
    parts = [p.lower() for p in folder.split("/") if p]
    for idx, kw in enumerate(_SHARED_FOLDER_PRIORITY):
        if kw in parts:
            return (0, f"{idx:02d}:{folder}")
    if any(p in {"tests", "test", "__tests__", "spec"} for p in parts):
        return (2, folder)
    return (1, folder)


def build_repo_map(
    repo_path: str | Path,
    *,
    max_chars: int = 2000,
    graph: CodeGraph | None = None,
) -> dict[str, Any]:
    """Build a compact (<= max_chars) prompt-injection-safe export map by folder."""
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars <= 0:
        raise AthenaValidationError(
            "INVALID_MAX_CHARS",
            f"max_chars must be a positive integer (got {max_chars!r}).",
        )
    max_chars = max(256, min(max_chars, 16000))
    cg = graph if graph is not None else DEFAULT_GRAPH_MANAGER.get_or_build(repo_path)

    exports_by_folder: dict[str, list[str]] = defaultdict(list)
    seen_per_folder: dict[str, set[str]] = defaultdict(set)

    for node in cg.nodes:
        if node.kind == "module":
            continue
        folder = Path(node.file_path).parent.as_posix()
        if folder == ".":
            folder = "root"
        safe_folder = _sanitize_token(folder, _SAFE_PATH_RE)
        safe_sym = _sanitize_token(node.label.split(".")[-1], _SAFE_IDENT_RE)
        if not safe_folder or not safe_sym:
            continue
        if safe_sym.startswith("_") and not safe_sym.startswith("__"):
            continue
        if safe_sym not in seen_per_folder[safe_folder]:
            seen_per_folder[safe_folder].add(safe_sym)
            exports_by_folder[safe_folder].append(safe_sym)

    ordered_folders = sorted(exports_by_folder.keys(), key=_folder_priority)
    lines: list[str] = [f"# Athena Repo Map ({len(cg.nodes)} symbols, completeness={cg.completeness})"]
    used = len(lines[0])

    for folder in ordered_folders:
        syms = sorted(exports_by_folder[folder])[:12]
        line = f"{folder}: {', '.join(syms)}"
        if used + len(line) + 1 > max_chars:
            remaining = max_chars - used - 4
            if remaining > len(folder) + 6:
                lines.append(line[:remaining] + "...")
            break
        lines.append(line)
        used += len(line) + 1

    map_text = "\n".join(lines)
    return {
        "status": "ok",
        "repo_root": cg.repo_root,
        "graph_evidence_id": cg.graph_evidence_id,
        "completeness": cg.completeness,
        "char_count": len(map_text),
        "max_chars": max_chars,
        "folders_included": max(0, len(lines) - 1),
        "map_text": map_text,
    }
