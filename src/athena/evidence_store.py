"""Cryptographic Content-Addressed Evidence, Residual Unknowns, and Retained Paging Store.

Distills `morluto/rea`'s epistemic provenance model (`ev_<sha256>`, `unk_<sha256>`,
summary-first retained delivery, and typed resource-constraint errors) into Athena's
local-first Python 3.12-3.15+ architecture.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel

from athena.security import redact_secrets, redact_sensitive_data

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


class EvidenceStore:
    """Thread-safe LRU store for retained full analysis payloads with paged view inspection."""

    def __init__(self, max_entries: int = 32) -> None:
        self._max_entries = max(1, max_entries)
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, _RetainedEntry] = OrderedDict()

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
        """Return True if an evidence bundle is retained in memory."""
        with self._lock:
            return evidence_id in self._entries

    def list_retained(self) -> list[dict[str, Any]]:
        """List metadata for all currently retained evidence bundles."""
        with self._lock:
            return [
                {
                    "evidence_id": e.evidence_id,
                    "kind": e.kind,
                    "completeness": e.completeness,
                    "facets": [k for k, v in e.payload.items() if isinstance(v, (list, dict))],
                }
                for e in reversed(self._entries.values())
            ]

    def inspect_view(
        self,
        evidence_id: str,
        facet: str,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Page through a specific facet (list or dict) of a retained evidence bundle."""
        offset = max(offset, 0)
        limit = max(limit, 1)
        limit = min(limit, 200)

        with self._lock:
            entry = self._entries.get(evidence_id)
            if entry is not None:
                self._entries.move_to_end(evidence_id)

        if entry is None:
            return {
                "status": "error",
                "error_code": "EVIDENCE_NOT_FOUND",
                "error_message": (
                    f"No retained evidence found for '{evidence_id}'. "
                    "Run the analysis tool again with detail='summary' or detail='complete'."
                ),
            }

        if facet not in entry.payload:
            available = [k for k, v in entry.payload.items() if isinstance(v, (list, dict))]
            return {
                "status": "error",
                "error_code": "FACET_NOT_FOUND",
                "error_message": f"Facet '{facet}' not found in '{evidence_id}'.",
                "available_facets": available,
            }

        target = entry.payload[facet]
        if isinstance(target, list):
            total = len(target)
            items = target[offset : offset + limit]
            return {
                "status": "ok",
                "evidence_id": evidence_id,
                "kind": entry.kind,
                "completeness": entry.completeness,
                "facet": facet,
                "offset": offset,
                "limit": limit,
                "total": total,
                "has_more": offset + len(items) < total,
                "items": items,
            }
        if isinstance(target, dict):
            keys = sorted(target.keys())
            total = len(keys)
            sliced_keys = keys[offset : offset + limit]
            return {
                "status": "ok",
                "evidence_id": evidence_id,
                "kind": entry.kind,
                "completeness": entry.completeness,
                "facet": facet,
                "offset": offset,
                "limit": limit,
                "total": total,
                "has_more": offset + len(sliced_keys) < total,
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


DEFAULT_EVIDENCE_STORE = EvidenceStore(max_entries=32)
