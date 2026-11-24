"""Predictive Test Selection from AST Blast Radius & Code Graph (`athena affected-tests`).

Implements Mateusz Wróbel's suggestion: maps modified/broken symbols and affected
downstream callers directly to the pytest, Playwright, or unit test files that exercise them.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from athena.evidence_store import paginate_items
from athena.git_inspector import MAX_SOURCE_BLOB_BYTES, extract_revision_range_data
from athena.graph_store import _collect_tracked_source_files, _is_test_or_utility_path
from athena.security import validate_repo_path

_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_E2E_MARKERS = (".spec.ts", ".spec.js", ".e2e.ts", ".e2e.js", "playwright")


def predict_affected_tests(
    repo_path: str | Path,
    *,
    base_ref: str = "AUTO",
    target_ref: str = "HEAD",
    offset: int = 0,
    limit: int | None = None,
) -> dict[str, Any]:
    """Select test files (pytest, Playwright, unit/e2e) impacted by changes in base_ref..target_ref."""
    _, _, _, _ = paginate_items((), offset=offset, limit=limit, max_limit=500, strict=True)
    repo_root = validate_repo_path(repo_path)
    extraction = extract_revision_range_data(
        repo_path_input=repo_root,
        base_ref=base_ref,
        target_ref=target_ref,
        max_commits=100,
    )

    changed_paths = [cf.file_path for cf in extraction.changed_files]
    changed_stems = {Path(p).stem for p in changed_paths if Path(p).stem}
    changed_idents: set[str] = set()
    for p in changed_paths:
        blob = extraction.target_blobs.get(p) or extraction.base_blobs.get(p) or ""
        for tok in _IDENT_RE.findall(blob):
            if len(tok) >= 4:
                changed_idents.add(tok)

    all_files = _collect_tracked_source_files(repo_root)
    test_files = [
        f
        for f in all_files
        if _is_test_or_utility_path(f.relative_to(repo_root).as_posix())
    ]

    selected: list[dict[str, Any]] = []
    for tf in test_files:
        rel = tf.relative_to(repo_root).as_posix()
        try:
            raw = tf.read_bytes()
        except OSError:
            continue
        if len(raw) > MAX_SOURCE_BLOB_BYTES:
            continue
        text = raw.decode("utf-8", errors="replace")
        if rel in changed_paths:
            selected.append({"test_file": rel, "reason": "test_file_modified", "is_e2e": any(m in rel.lower() for m in _E2E_MARKERS)})
            continue

        matched_stems = sorted(s for s in changed_stems if len(s) >= 3 and s in text)
        matched_syms = sorted(s for s in changed_idents if s in text)[:5]
        if matched_stems or matched_syms:
            selected.append(
                {
                    "test_file": rel,
                    "reason": "references_changed_module_or_symbol",
                    "matched_modules": matched_stems[:5],
                    "matched_symbols": matched_syms,
                    "is_e2e": any(m in rel.lower() for m in _E2E_MARKERS),
                }
            )

    paged_selected, total_matched, effective_limit, has_more = paginate_items(
        selected,
        offset=offset,
        limit=limit,
        max_limit=500,
        strict=True,
    )
    return {
        "status": "ok",
        "repo_root": str(repo_root),
        "base_ref": extraction.base_ref,
        "target_ref": extraction.target_ref,
        "total_test_files": len(test_files),
        "selected_count": total_matched,
        "returned_count": len(paged_selected),
        "offset": offset,
        "limit": effective_limit,
        "has_more": has_more,
        "partial": has_more,
        "selected_tests": paged_selected,
    }
