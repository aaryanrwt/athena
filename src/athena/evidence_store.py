"""Cryptographic Content-Addressed Evidence, Residual Unknowns, and Retained Paging Store.

Provides SHA-256 content-addressed provenance (`ev_<sha256>`, `unk_<sha256>`),
summary-first retained delivery across in-process and cross-process calls,
bounded pagination, and typed resource-constraint errors.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
from collections import OrderedDict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Literal, TypeVar

from pydantic import BaseModel

from athena.security import (
    AthenaValidationError,
    redact_secrets,
    redact_sensitive_data,
)

_T = TypeVar("_T")
_EVIDENCE_ID_RE = re.compile(r"^ev_[0-9a-f]{64}$")

EvidenceConfidence = Literal["observed", "derived", "inferred"]
CompletenessStatus = Literal["complete", "partial", "unknown"]
UnknownStatus = Literal["open", "investigating", "blocked", "contradicted", "resolved"]
UnknownKind = Literal[
    "dynamic_dispatch",
    "unresolved_import",
    "shallow_repo",
    "binary_or_oversized",
    "parser_partial",
    "budget_truncated",
]

_VOLATILE_DIGEST_KEYS = frozenset(
    {
        "caller_input_path",
        "caller_input_paths",
        "evidence_format",
        "generated_at",
        "elapsed_ms",
    }
)


def _canonicalize_value(value: Any) -> Any:
    """Recursively normalize a value for deterministic RFC-8785-style JSON hashing."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        return {
            str(k): _canonicalize_value(v)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
            if str(k) not in _VOLATILE_DIGEST_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalize_value(item) for item in value]
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value
    return value


def canonical_digest(payload: Any) -> str:
    """Compute a deterministic SHA-256 hex digest over canonicalized JSON."""
    normalized = _canonicalize_value(payload)
    encoded = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_evidence_id(payload: Any) -> str:
    """Return a content-addressed `ev_<sha256>` identifier."""
    return f"ev_{canonical_digest(payload)}"


def canonical_unknown_id(payload: Any) -> str:
    """Return a content-addressed `unk_<sha256>` identifier."""
    return f"unk_{canonical_digest(payload)}"


class ResidualUnknownRecord(BaseModel):
    """Durable record of an unresolved dynamic call, partial parse, or coverage gap."""

    unknown_id: str
    kind: UnknownKind
    status: UnknownStatus = "open"
    severity: Literal["low", "medium", "high"] = "medium"
    file_path: str
    line: int = 0
    symbol: str = ""
    detail: str
    remediation: str = ""


class AnalysisResourceConstraintError(RuntimeError):
    """Typed error for bounded resource limits (blob size, shallow repo, timeout, budget)."""

    def __init__(
        self,
        resource: Literal["memory", "cpu", "file_size", "transport", "capacity", "git_history"],
        message: str,
        *,
        retryable: bool = True,
        remediation_action: str = "",
    ) -> None:
        super().__init__(redact_secrets(message))
        self.resource = resource
        self.retryable = retryable
        self.remediation_action = remediation_action

    def to_dict(self) -> dict[str, Any]:
        """Serialize as a structured MCP/CLI error payload."""
        return {
            "status": "error",
            "error_kind": "resource_constraint",
            "resource": self.resource,
            "retryable": self.retryable,
            "error_message": str(self),
            "remediation_action": self.remediation_action,
        }


def resolve_completeness(
    *,
    skipped_files: int = 0,
    unresolved_unknowns: int = 0,
    truncated: bool = False,
    parse_errors: int = 0,
) -> CompletenessStatus:
    """Determine completeness strictly; never defaults to 'complete' when gaps exist."""
    if parse_errors > 0 or truncated:
        return "partial"
    if skipped_files > 0 or unresolved_unknowns > 0:
        return "partial"
    return "complete"


class _RetainedEntry:
    __slots__ = ("completeness", "evidence_id", "kind", "payload")

    def __init__(
        self,
        evidence_id: str,
        kind: str,
        payload: dict[str, Any],
        completeness: CompletenessStatus,
    ) -> None:
        self.evidence_id = evidence_id
        self.kind = kind
        self.payload = payload
        self.completeness = completeness


def paginate_items(
    items: Sequence[_T],
    *,
    offset: int = 0,
    limit: int | None = None,
    max_limit: int = 500,
    strict: bool = True,
) -> tuple[list[_T], int, int | None, bool]:
    """Slice a sequence safely with bounded limit and optional strict validation."""
    if strict:
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise AthenaValidationError(
                "INVALID_OFFSET",
                f"offset must be a non-negative integer (got {offset!r}).",
            )
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
            raise AthenaValidationError(
                "INVALID_LIMIT",
                f"limit must be a positive integer (got {limit!r}).",
            )
    else:
        offset = max(0, int(offset))
        if limit is not None:
            limit = max(1, int(limit))

    items_list = list(items)
    total = len(items_list)
    if limit is None:
        sliced = items_list[offset:]
        return sliced, total, None, False

    effective_limit = min(limit, max_limit)
    sliced = items_list[offset : offset + effective_limit]
    has_more = (offset + len(sliced)) < total
    return sliced, total, effective_limit, has_more


class EvidenceStore:
    """Thread-safe LRU store for retained full analysis payloads with optional disk persistence."""

    def __init__(
        self,
        max_entries: int = 32,
        *,
        persist_dir: str | Path | None = None,
        use_env_dir: bool = False,
    ) -> None:
        self._max_entries = max(1, max_entries)
        self._persist_dir = Path(persist_dir) if persist_dir is not None else None
        self._use_env_dir = use_env_dir
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, _RetainedEntry] = OrderedDict()

    def _storage_dir(self) -> Path | None:
        if self._persist_dir is not None:
            return self._persist_dir
        if not self._use_env_dir:
            return None
        override = os.environ.get("ATHENA_EVIDENCE_DIR", "").strip()
        if override:
            return Path(override)
        return Path.home() / ".athena" / "evidence"

    @staticmethod
    def _entry_path(storage_dir: Path, evidence_id: str) -> Path | None:
        if not _EVIDENCE_ID_RE.match(evidence_id):
            return None
        try:
            if storage_dir.is_symlink():
                return None
            root = storage_dir.resolve()
            candidate = (root / f"{evidence_id}.json").resolve()
            if not candidate.is_relative_to(root) or candidate.parent != root or candidate.is_symlink():
                return None
            return candidate
        except OSError:
            return None

    def _prune_disk_entries(self, storage_dir: Path) -> None:
        try:
            if storage_dir.is_symlink():
                return
            root = storage_dir.resolve()
            if not root.is_dir():
                return
            files: list[Path] = []
            for p in root.iterdir():
                if p.is_symlink() or not p.is_file() or p.suffix != ".json":
                    continue
                if not _EVIDENCE_ID_RE.match(p.stem):
                    continue
                resolved = p.resolve()
                if resolved.is_relative_to(root) and resolved.parent == root:
                    files.append(p)
            if len(files) <= self._max_entries:
                return
            files.sort(key=lambda p: (p.stat().st_mtime, p.name))
            for stale in files[: len(files) - self._max_entries]:
                if stale.is_symlink():
                    continue
                resolved_stale = stale.resolve()
                if (
                    _EVIDENCE_ID_RE.match(resolved_stale.stem)
                    and resolved_stale.is_relative_to(root)
                    and resolved_stale.parent == root
                ):
                    resolved_stale.unlink(missing_ok=True)
        except OSError:
            return

    def _persist_entry(self, entry: _RetainedEntry) -> None:
        storage_dir = self._storage_dir()
        if storage_dir is None:
            return
        try:
            if storage_dir.is_symlink():
                return
            storage_dir.mkdir(parents=True, exist_ok=True)
            dest = self._entry_path(storage_dir, entry.evidence_id)
            if dest is None:
                return
            envelope = {
                "schema_version": "1.0",
                "evidence_id": entry.evidence_id,
                "kind": entry.kind,
                "completeness": entry.completeness,
                "payload": entry.payload,
            }
            raw = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
            tmp_path = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
            tmp_path.write_text(raw, encoding="utf-8")
            os.replace(tmp_path, dest)
            self._prune_disk_entries(storage_dir)
        except OSError:
            return

    def _load_from_disk(self, evidence_id: str) -> _RetainedEntry | None:
        storage_dir = self._storage_dir()
        if storage_dir is None:
            return None
        dest = self._entry_path(storage_dir, evidence_id)
        if dest is None or not dest.is_file():
            return None
        try:
            data = json.loads(dest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict) or data.get("evidence_id") != evidence_id:
            return None
        payload = data.get("payload")
        kind = data.get("kind")
        completeness = data.get("completeness", "unknown")
        if not isinstance(payload, dict) or not isinstance(kind, str):
            return None
        if completeness not in {"complete", "partial", "unknown"}:
            completeness = "unknown"
        entry = _RetainedEntry(
            evidence_id=evidence_id,
            kind=kind,
            payload=redact_sensitive_data(payload),
            completeness=completeness,
        )
        try:
            os.utime(dest, None)
        except OSError:
            pass
        return entry

    def retain(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        completeness: CompletenessStatus = "unknown",
        summary_builder: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Store full payload under its canonical `ev_<sha256>` ID and return a summary."""
        safe_payload = redact_sensitive_data(payload)
        ev_id = canonical_evidence_id({"kind": kind, "payload": safe_payload})
        entry = _RetainedEntry(
            evidence_id=ev_id,
            kind=kind,
            payload=safe_payload,
            completeness=completeness,
        )
        with self._lock:
            self._entries.pop(ev_id, None)
            self._entries[ev_id] = entry
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
        self._persist_entry(entry)

        facets = [k for k, v in safe_payload.items() if isinstance(v, (list, dict))]
        if summary_builder is not None:
            summary = summary_builder(ev_id, safe_payload)
        else:
            summary = {
                "status": safe_payload.get("status", "ok"),
                "detail": "summary",
                "parent_evidence_id": ev_id,
                "kind": kind,
                "completeness": completeness,
                "available_facets": facets,
                "counts": {
                    k: len(v)
                    for k, v in safe_payload.items()
                    if isinstance(v, (list, dict))
                },
            }
        summary.setdefault("parent_evidence_id", ev_id)
        summary.setdefault("completeness", completeness)
        summary.setdefault("available_facets", facets)
        return redact_sensitive_data(summary)

    def has(self, evidence_id: str) -> bool:
        """Return True if an evidence bundle is retained in memory or on disk."""
        with self._lock:
            if evidence_id in self._entries:
                return True
        loaded = self._load_from_disk(evidence_id)
        if loaded is None:
            return False
        with self._lock:
            self._entries.pop(evidence_id, None)
            self._entries[evidence_id] = loaded
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
        return True

    def list_retained(self) -> list[dict[str, Any]]:
        """List metadata for all currently retained evidence bundles (memory + disk)."""
        seen: dict[str, dict[str, Any]] = {}
        with self._lock:
            for e in reversed(self._entries.values()):
                seen[e.evidence_id] = {
                    "evidence_id": e.evidence_id,
                    "kind": e.kind,
                    "completeness": e.completeness,
                    "facets": [k for k, v in e.payload.items() if isinstance(v, (list, dict))],
                }

        storage_dir = self._storage_dir()
        if storage_dir is not None and storage_dir.is_dir():
            try:
                files = sorted(
                    (p for p in storage_dir.glob("ev_*.json") if p.is_file() and not p.is_symlink()),
                    key=lambda p: (p.stat().st_mtime, p.name),
                    reverse=True,
                )
            except OSError:
                files = []
            for p in files[: self._max_entries]:
                ev_id = p.stem
                if ev_id in seen or not _EVIDENCE_ID_RE.match(ev_id):
                    continue
                loaded = self._load_from_disk(ev_id)
                if loaded is not None:
                    seen[loaded.evidence_id] = {
                        "evidence_id": loaded.evidence_id,
                        "kind": loaded.kind,
                        "completeness": loaded.completeness,
                        "facets": [k for k, v in loaded.payload.items() if isinstance(v, (list, dict))],
                    }
        return list(seen.values())[: self._max_entries]

    def inspect_view(
        self,
        evidence_id: str,
        facet: str,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Page through a specific facet (list or dict) of a retained evidence bundle."""
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            return {
                "status": "error",
                "error_code": "INVALID_OFFSET",
                "error_kind": "validation",
                "retryable": False,
                "error_message": f"offset must be a non-negative integer (got {offset!r}).",
                "remediation_action": "Pass offset >= 0.",
            }
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            return {
                "status": "error",
                "error_code": "INVALID_LIMIT",
                "error_kind": "validation",
                "retryable": False,
                "error_message": f"limit must be a positive integer (got {limit!r}).",
                "remediation_action": "Pass limit between 1 and 200.",
            }

        with self._lock:
            entry = self._entries.get(evidence_id)
            if entry is not None:
                self._entries.move_to_end(evidence_id)

        if entry is None:
            loaded = self._load_from_disk(evidence_id)
            if loaded is not None:
                with self._lock:
                    self._entries.pop(evidence_id, None)
                    self._entries[evidence_id] = loaded
                    while len(self._entries) > self._max_entries:
                        self._entries.popitem(last=False)
                entry = loaded

        if entry is None:
            return {
                "status": "error",
                "error_code": "EVIDENCE_NOT_FOUND",
                "error_kind": "not_found",
                "retryable": True,
                "error_message": (
                    f"No retained evidence found for '{evidence_id}'. "
                    "Run the analysis tool again with detail='summary' or detail='complete'."
                ),
                "remediation_action": "Run analyze, breaking-changes, or query_code_graph with detail='summary' first.",
            }

        if facet not in entry.payload:
            available = [k for k, v in entry.payload.items() if isinstance(v, (list, dict))]
            return {
                "status": "error",
                "error_code": "FACET_NOT_FOUND",
                "error_kind": "invalid_input",
                "retryable": False,
                "error_message": f"Facet '{facet}' not found in '{evidence_id}'.",
                "available_facets": available,
                "remediation_action": f"Choose one of available_facets: {available}",
            }

        target = entry.payload[facet]
        if isinstance(target, list):
            items, total, effective_limit, has_more = paginate_items(
                target,
                offset=offset,
                limit=limit,
                max_limit=200,
                strict=False,
            )
            return {
                "status": "ok",
                "evidence_id": evidence_id,
                "kind": entry.kind,
                "completeness": entry.completeness,
                "facet": facet,
                "offset": max(0, int(offset)),
                "limit": effective_limit,
                "total": total,
                "has_more": has_more,
                "items": items,
            }
        if isinstance(target, dict):
            keys = sorted(target.keys())
            sliced_keys, total, effective_limit, has_more = paginate_items(
                keys,
                offset=offset,
                limit=limit,
                max_limit=200,
                strict=False,
            )
            return {
                "status": "ok",
                "evidence_id": evidence_id,
                "kind": entry.kind,
                "completeness": entry.completeness,
                "facet": facet,
                "offset": max(0, int(offset)),
                "limit": effective_limit,
                "total": total,
                "has_more": has_more,
                "items": {k: target[k] for k in sliced_keys},
            }

        return {
            "status": "ok",
            "evidence_id": evidence_id,
            "kind": entry.kind,
            "completeness": entry.completeness,
            "facet": facet,
            "value": target,
        }


DEFAULT_EVIDENCE_STORE = EvidenceStore(max_entries=32, use_env_dir=True)
