"""Aggregate one or more scale-evaluation ledgers (JSONL) into a markdown report.

Every figure is computed directly from ledger records; nothing is estimated or extrapolated.

Usage:
    python aggregate_report.py --ledger cache/scale/scale_ledger.jsonl [--ledger other.jsonl] \
        --out results/SCALE_REPORT.md
"""

from __future__ import annotations

import argparse
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from run_scale_evaluation import load_ledger


def _pct(vals: list[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(records)
    status = Counter(r.get("status", "unknown") for r in records)
    ok = [r for r in records if r.get("status") == "passed"]
    walls = [float(r.get("wall_seconds", 0)) for r in records]
    by_lang: dict[str, Counter] = defaultdict(Counter)
    for r in records:
        by_lang[r.get("primary_language") or "Unknown"][r.get("status", "unknown")] += 1
    reasons = Counter()
    for r in records:
        if r.get("status") in ("failed", "timeout", "crashed"):
            reasons[(r.get("failure_reason") or "unknown")[:90]] += 1

    def total(key: str) -> int:
        return int(sum(r.get(key) or 0 for r in ok))

    return {
        "n": n, "status": status, "ok": len(ok), "by_lang": by_lang, "reasons": reasons,
        "commits_inspected": total("commits_inspected"), "files_changed": total("files_changed"),
        "symbol_changes": total("symbol_changes_count"), "breaking": total("breaking_changes_count"),
        "findings": total("findings_count"),
        "repos_with_breaking": sum(1 for r in ok if (r.get("breaking_changes_count") or 0) > 0),
        "evidence_ok": sum(1 for r in ok if r.get("evidence_integrity_status") == "passed"),
        "wall_total": sum(walls),
        "wall_mean": statistics.mean(walls) if walls else 0.0,
        "wall_median": statistics.median(walls) if walls else 0.0,
        "wall_p95": _pct(walls, 95), "wall_max": max(walls) if walls else 0.0,
    }


def render(ledgers: dict[str, dict[str, dict[str, Any]]]) -> str:
    lines = ["# Athena Scale Evaluation Report", "",
             "All numbers below are measured from the ledger files listed; nothing is extrapolated.", ""]
    for name, led in ledgers.items():
        recs = list(led.values())
        s = summarize(recs)
        mode = recs[0].get("mode", "unknown") if recs else "unknown"
        lines += [f"## {name} (mode: {mode})", ""]
        if not recs:
            lines += ["_No records._", ""]
            continue
        n = s["n"]
        lines += ["| Metric | Value |", "|---|---|", f"| Repositories attempted | {n} |"]
        for st in ("passed", "insufficient_history", "failed", "timeout", "crashed"):
            if s["status"].get(st):
                lines.append(f"| {st} | {s['status'][st]} ({100 * s['status'][st] / n:.1f}%) |")
        lines += [
            f"| Commits inspected (passed repos) | {s['commits_inspected']:,} |",
            f"| Files changed (passed repos) | {s['files_changed']:,} |",
            f"| Symbol changes detected | {s['symbol_changes']:,} |",
            f"| Potential breaking-change findings | {s['breaking']:,} |",
            f"| Passed repos with >=1 breaking finding | {s['repos_with_breaking']} |",
            f"| Passed repos with intact evidence links | {s['evidence_ok']} / {s['ok']} |",
            f"| Wall time total / mean / median / p95 / max (s) | {s['wall_total']:.0f} / {s['wall_mean']:.1f} / "
            f"{s['wall_median']:.1f} / {s['wall_p95']:.1f} / {s['wall_max']:.1f} |", ""]
        lines += ["### By language", "", "| Language | Attempted | Passed | Other |", "|---|---|---|---|"]
        for lang, c in sorted(s["by_lang"].items(), key=lambda kv: -sum(kv[1].values())):
            t = sum(c.values())
            lines.append(f"| {lang} | {t} | {c.get('passed', 0)} | {t - c.get('passed', 0)} |")
        lines.append("")
        if s["reasons"]:
            lines += ["### Failure reasons (top 10)", ""]
            lines += [f"- {cnt} x {r}" for r, cnt in s["reasons"].most_common(10)] + [""]
    lines += ["## Notes", "",
              "- Findings are static-analysis candidates; precision/recall against ground truth is not measured here.",
              "- Repos are shallow-cloned; commit windows are limited to the configured history depth.", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ledger", action="append", required=True)
    ap.add_argument("--out", default=str(Path(__file__).parent / "results" / "SCALE_REPORT.md"))
    a = ap.parse_args()
    ledgers = {Path(p).name: load_ledger(Path(p)) for p in a.ledger}
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(ledgers), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
