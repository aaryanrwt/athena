"""SARIF 2.1.0 serialization for breaking-change reports."""

from __future__ import annotations

from typing import Any

from athena import __version__

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {"high": "error", "medium": "warning", "low": "note"}


def _relative_uri(path: str) -> str:
    """Normalize to a repo-relative POSIX URI with no drive, root, or parent segments."""
    norm = (path or "").replace("\\", "/")
    if len(norm) >= 2 and norm[1] == ":":
        norm = norm[2:]
    parts = [p for p in norm.split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "unknown"


def _region(span: dict[str, Any] | None) -> dict[str, int] | None:
    if not span:
        return None
    start = max(1, int(span.get("start_line", 1)))
    end = max(start, int(span.get("end_line", start)))
    return {"startLine": start, "endLine": end}


def _location(path: str, span: dict[str, Any] | None, message: str | None = None) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": _relative_uri(path), "uriBaseId": "%SRCROOT%"}}
    region = _region(span)
    if region:
        physical["region"] = region
    loc: dict[str, Any] = {"physicalLocation": physical}
    if message:
        loc["message"] = {"text": message}
    return loc


def breaking_report_to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Convert a ``BreakingChangeReport`` dict into a SARIF 2.1.0 log."""
    registry = report.get("evidence_registry") or {}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.get("potential_breaking_changes") or []:
        kind = str(finding.get("change_kind") or "breaking_change")
        rule_id = f"athena/{kind}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": kind,
                "shortDescription": {"text": f"Potential breaking change: {kind}"},
                "fullDescription": {
                    "text": "Potential breaking change detected by deterministic AST/diff analysis; requires human review."
                },
            },
        )

        records = [registry[e] for e in finding.get("evidence_ids") or [] if e in registry]
        records.extend(finding.get("evidence") or [])
        seen: set[str] = set()
        evidence: list[dict[str, Any]] = []
        for rec in records:
            ident = str(rec.get("evidence_id"))
            if ident not in seen:
                seen.add(ident)
                evidence.append(rec)

        primary_span = None
        for rec in evidence:
            primary_span = rec.get("target_line_span") or rec.get("base_line_span")
            if primary_span:
                break

        text = finding.get("title") or kind
        sym = finding.get("affected_symbol")
        if sym:
            text = f"{text} ({sym})"
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _LEVELS.get(str(finding.get("severity")), "warning"),
            "message": {"text": text},
            "locations": [_location(str(finding.get("file_path", "")), primary_span)],
            "partialFingerprints": {"athenaFindingId": str(finding.get("finding_id", ""))},
            "properties": {
                "confidence": finding.get("confidence"),
                "isPublicApiExport": bool(finding.get("is_public_api_export")),
                "evidenceIds": [str(r.get("evidence_id")) for r in evidence],
                "requiresHumanReview": True,
            },
        }
        related = []
        for idx, rec in enumerate(evidence):
            span = rec.get("target_line_span") or rec.get("base_line_span")
            loc = _location(str(rec.get("file_path", "")), span, str(rec.get("reason_supports_finding") or ""))
            loc["id"] = idx
            related.append(loc)
        if related:
            result["relatedLocations"] = related
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "athena",
                        "version": __version__,
                        "informationUri": "https://github.com/aaryanrwt/athena",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
