"""Single-file, fully static HTML breaking-change report (no scripts, no external assets)."""

from __future__ import annotations

from html import escape
from typing import Any

from athena import __version__
from athena.security import redact_secrets

_CSS = (
    "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#1b1f23}"
    "h1{margin-bottom:.2rem}.meta{color:#57606a}"
    "section.finding{border:1px solid #d0d7de;border-radius:6px;padding:.8rem 1rem;margin:1rem 0}"
    ".sev-high{border-left:6px solid #cf222e}.sev-medium{border-left:6px solid #bf8700}"
    ".sev-low{border-left:6px solid #57606a}"
    "pre{background:#f6f8fa;padding:.6rem;overflow:auto;white-space:pre-wrap}"
    "code{background:#f6f8fa;padding:0 .2rem}table{border-collapse:collapse}"
    "td,th{border:1px solid #d0d7de;padding:.2rem .5rem;text-align:left}"
)


def _e(value: Any) -> str:
    """Redact credentials, then HTML-escape (including quotes) any value."""
    return escape(redact_secrets("" if value is None else str(value)), quote=True)


def _list(items: list[Any]) -> str:
    if not items:
        return ""
    return "<ul>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>"


def render_html_report(report: dict[str, Any]) -> str:
    """Render a ``BreakingChangeReport`` dict as a self-contained HTML document."""
    registry = report.get("evidence_registry") or {}
    findings = report.get("potential_breaking_changes") or []
    out: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Athena breaking-change report</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>Athena breaking-change report</h1>",
        f'<p class="meta">Athena {_e(__version__)} &middot; base <code>{_e(report.get("base_ref"))}</code> '
        f'({_e(str(report.get("resolved_base_sha", ""))[:12])}) &rarr; target <code>{_e(report.get("target_ref"))}</code> '
        f'({_e(str(report.get("resolved_target_sha", ""))[:12])})</p>',
    ]
    if report.get("status") != "ok":
        out.append(
            f"<p><strong>Error:</strong> {_e(report.get('error_code'))}: {_e(report.get('error_message'))}</p>"
        )
        out.append("</body></html>")
        return "\n".join(out) + "\n"

    out.append(f"<p>{_e(report.get('epistemic_notice'))}</p>")
    out.append(f"<h2>Potential breaking changes: {len(findings)}</h2>")
    if not findings:
        out.append("<p>No potential breaking changes detected.</p>")
    for f in findings:
        sev = str(f.get("severity", "medium"))
        sev_cls = sev if sev in ("high", "medium", "low") else "medium"
        out.append(f'<section class="finding sev-{sev_cls}">')
        out.append(f"<h3>{_e(f.get('title'))}</h3>")
        out.append(
            f"<p><strong>{_e(sev)}</strong> severity &middot; {_e(f.get('confidence'))} confidence &middot; "
            f"<code>{_e(f.get('file_path'))}</code> &middot; kind <code>{_e(f.get('change_kind'))}</code>"
            + (f" &middot; symbol <code>{_e(f.get('affected_symbol'))}</code>" if f.get("affected_symbol") else "")
            + "</p>"
        )
        if f.get("old_signature") or f.get("new_signature"):
            out.append(
                f"<pre>- {_e(f.get('old_signature'))}\n+ {_e(f.get('new_signature'))}</pre>"
            )
        for heading, key in (
            ("Observed facts", "observed_facts"),
            ("Risks requiring verification", "potential_risks_requiring_verification"),
        ):
            if f.get(key):
                out.append(f"<h4>{heading}</h4>{_list(f[key])}")
        if f.get("model_interpretation"):
            out.append(f"<p>{_e(f.get('model_interpretation'))}</p>")
        callers = f.get("affected_callers") or []
        if callers:
            out.append("<h4>Affected callers</h4><table><tr><th>File</th><th>Line</th><th>Snippet</th></tr>")
            for c in callers:
                out.append(
                    f"<tr><td>{_e(c.get('caller_file'))}</td><td>{_e(c.get('line_number'))}</td>"
                    f"<td><code>{_e(c.get('call_snippet'))}</code></td></tr>"
                )
            out.append("</table>")
        evidence = [registry[e] for e in f.get("evidence_ids") or [] if e in registry] or (f.get("evidence") or [])
        for rec in evidence:
            out.append(
                f"<h4>Evidence {_e(rec.get('evidence_id'))}</h4>"
                f"<p><code>{_e(rec.get('file_path'))}</code> &middot; {_e(rec.get('reason_supports_finding'))}</p>"
            )
            if rec.get("diff_excerpt"):
                out.append(f"<pre>{_e(rec.get('diff_excerpt'))}</pre>")
        out.append("</section>")

    if report.get("warnings"):
        out.append(f"<h2>Warnings</h2>{_list(report['warnings'])}")
    out.append("</body></html>")
    return "\n".join(out) + "\n"
