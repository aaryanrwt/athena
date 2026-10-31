"""Render the sticky PR comment body for the Athena GitHub Action.

Reads the JSON emitted by ``athena breaking-changes`` and writes Markdown that
begins with a hidden marker so the action can find and update one comment.
Stdlib only; no network access.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

MARKER = "<!-- athena-breaking-changes -->"
MAX_FINDINGS = 25


def _esc(text: object) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def render(report: dict) -> str:
    cov = report.get("analysis_coverage") or {}
    findings = report.get("potential_breaking_changes") or []
    total = report.get("total_potential_breaking_changes", len(findings))
    lines = [MARKER, "## Athena: breaking-change & caller audit", ""]
    if total:
        lines.append(f"**{total} potential breaking change(s)** need human review.")
    else:
        lines.append("No potential breaking changes detected in this range.")
    lines += [
        "",
        f"Range: `{_esc(report.get('base_ref'))}` (`{str(report.get('resolved_base_sha', ''))[:8]}`)"
        f" -> `{_esc(report.get('target_ref'))}` (`{str(report.get('resolved_target_sha', ''))[:8]}`)",
        "",
    ]
    if findings:
        lines += [
            "| Severity | Symbol | Change | File | Callers |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for f in findings[:MAX_FINDINGS]:
            callers = f.get("affected_callers") or []
            where = ", ".join(
                f"`{_esc(c.get('caller_file'))}:{_esc(c.get('line_number'))}`" for c in callers[:3]
            )
            if len(callers) > 3:
                where += f" (+{len(callers) - 3} more)"
            lines.append(
                f"| {_esc(f.get('severity'))} | `{_esc(f.get('affected_symbol'))}` "
                f"| {_esc(f.get('change_kind'))} | `{_esc(f.get('file_path'))}` | {where or 'none found'} |"
            )
        if len(findings) > MAX_FINDINGS:
            lines.append(f"\n_Showing {MAX_FINDINGS} of {len(findings)} findings._")
        lines.append("")
    if cov:
        lines += [
            "<details><summary>Analysis coverage</summary>",
            "",
            f"- Static parse coverage: `{cov.get('static_parse_coverage_pct', 'n/a')}%`",
            f"- Unresolved dynamic calls: `{cov.get('unresolved_dynamic_calls_count', 'n/a')}`",
            f"- Blast-radius confidence: `{_esc(cov.get('overall_blast_radius_confidence', 'n/a'))}`",
            "",
            "</details>",
            "",
        ]
    lines.append("_Deterministic static analysis; findings require human review._")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: render_comment.py REPORT_JSON OUTPUT_MD", file=sys.stderr)
        return 2
    try:
        report = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        report = None
        body = f"{MARKER}\n## Athena: breaking-change & caller audit\n\nAthena could not produce a report ({type(exc).__name__}). See the workflow logs.\n"
    else:
        body = render(report)
    Path(argv[2]).write_text(body, encoding="utf-8")
    if report is not None:
        total = report.get("total_potential_breaking_changes", 0)
        print(total)
    else:
        print(-1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
