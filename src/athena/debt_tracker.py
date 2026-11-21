"""Technical Debt & `shortcut:` Ledger Scanner (`athena debt`).

Distills `ponytail-debt` with AST enclosing-symbol binding and safe bounded
file scanning (avoiding unbounded `git grep` memory spikes).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from pydantic import BaseModel, Field

from athena.evidence_store import canonical_evidence_id
from athena.git_inspector import MAX_SOURCE_BLOB_BYTES
from athena.graph_store import _collect_tracked_source_files
from athena.security import redact_secrets, validate_repo_path

_SHORTCUT_RE = re.compile(
    r"(?:#|//|/\*)\s*(shortcut|ponytail)\s*:\s*(.+?)(?:\*/)?$",
    re.IGNORECASE,
)
_TODO_RE = re.compile(
    r"(?:#|//|/\*)\s*(TODO|FIXME)\s*[:\-]?\s*(.+?)(?:\*/)?$",
    re.IGNORECASE,
)


class DebtItem(BaseModel):
    """A single tracked `shortcut:` or `TODO`/`FIXME` debt marker."""

    evidence_id: str
    marker: str
    file_path: str
    line: int
    enclosing_symbol: str = ""
    text: str
    has_upgrade_trigger: bool = False


class DebtReport(BaseModel):
    """Structured ledger of technical debt markers in a repository."""

    status: str = "ok"
    repo_root: str
    total_files_scanned: int
    total_shortcuts: int
    missing_trigger_count: int
    total_todos: int = 0
    items: list[DebtItem] = Field(default_factory=list)


def _python_enclosing_map(source: str) -> list[tuple[int, int, str]]:
    """Return `(start_line, end_line, symbol_name)` spans for Python defs/classes."""
    spans: list[tuple[int, int, str]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return spans
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end_ln = getattr(node, "end_lineno", node.lineno) or node.lineno
            spans.append((node.lineno, end_ln, node.name))
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    return spans


def _find_enclosing(spans: list[tuple[int, int, str]], line: int) -> str:
    best = ""
    best_len = 10**9
    for start, end, name in spans:
        if start <= line <= end and (end - start) < best_len:
            best = name
            best_len = end - start
    return best


def scan_shortcut_debt(
    repo_path: str | Path,
    *,
    include_todos: bool = False,
) -> DebtReport:
    """Scan repository source files for `shortcut: <limit>, <when to upgrade>` markers."""
    repo_root = validate_repo_path(repo_path)
    files = _collect_tracked_source_files(repo_root)
    items: list[DebtItem] = []
    shortcut_count = 0
    missing_trigger = 0
    todo_count = 0

    for file_path in files:
        try:
            raw = file_path.read_bytes()
        except OSError:
            continue
        if len(raw) > MAX_SOURCE_BLOB_BYTES:
            continue
        text = raw.decode("utf-8", errors="replace").lstrip("\ufeff")
        rel_path = file_path.relative_to(repo_root).as_posix()
        spans = _python_enclosing_map(text) if file_path.suffix.lower() in {".py", ".pyi"} else []

        for idx, line_str in enumerate(text.splitlines(), start=1):
            if len(line_str) > 512:
                continue
            m = _SHORTCUT_RE.search(line_str)
            if m:
                marker = m.group(1).lower()
                body = redact_secrets(m.group(2).strip())
                has_trigger = "," in body and len(body.split(",", 1)[1].strip()) >= 3
                shortcut_count += 1
                if not has_trigger:
                    missing_trigger += 1
                items.append(
                    DebtItem(
                        evidence_id=canonical_evidence_id({"file": rel_path, "line": idx, "marker": marker}),
                        marker=marker,
                        file_path=rel_path,
                        line=idx,
                        enclosing_symbol=_find_enclosing(spans, idx),
                        text=body,
                        has_upgrade_trigger=has_trigger,
                    )
                )
                continue

            if include_todos:
                m_todo = _TODO_RE.search(line_str)
                if m_todo:
                    todo_count += 1
                    items.append(
                        DebtItem(
                            evidence_id=canonical_evidence_id({"file": rel_path, "line": idx, "marker": m_todo.group(1).lower()}),
                            marker=m_todo.group(1).lower(),
                            file_path=rel_path,
                            line=idx,
                            enclosing_symbol=_find_enclosing(spans, idx),
                            text=redact_secrets(m_todo.group(2).strip()),
                            has_upgrade_trigger=False,
                        )
                    )

    return DebtReport(
        repo_root=str(repo_root),
        total_files_scanned=len(files),
        total_shortcuts=shortcut_count,
        missing_trigger_count=missing_trigger,
        total_todos=todo_count,
        items=items,
    )
