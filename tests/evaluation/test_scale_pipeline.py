"""Offline unit tests for the scale evaluation pipeline (no network, no git clones)."""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import aggregate_report as ar  # noqa: E402
import discover_repos as dr  # noqa: E402
import run_scale_evaluation as rs  # noqa: E402


def _item(name, stars, **kw):
    d = {"full_name": name, "stargazers_count": stars, "language": "Python",
         "archived": False, "fork": False, "clone_url": f"https://github.com/{name}.git"}
    d.update(kw)
    return d


def test_backoff_uses_retry_after_and_reset():
    assert dr.compute_backoff({"retry-after": "30"}, 0) == 31
    h = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1100"}
    assert dr.compute_backoff(h, 0, now=1000) == 102
    assert dr.compute_backoff({}, 1) == 20


def test_shard_splits_when_over_cap():
    calls = []

    def fetch(url):
        q = dict(p.split("=", 1) for p in url.split("?", 1)[1].split("&"))
        import urllib.parse as up
        query = up.unquote_plus(q["q"])
        lo = int(query.split("stars:")[1].split()[0].replace(">=", "").split("..")[0])
        hi_s = query.split("stars:")[1].split()[0]
        hi = int(hi_s.split("..")[1]) if ".." in hi_s else None
        calls.append((lo, hi))
        # Pretend 1 repo per 1000 stars up to 40000; cap total_count at actual number.
        top = hi if hi is not None else 40000
        n = max(0, (top - lo) // 100 + 1)
        items = [_item(f"o/r{lo}_{i}", lo + i) for i in range(min(n, 100))]
        return 200, {}, {"total_count": n, "items": items}

    out = dr.shard_search(fetch, 10000, None, "2026-01-01")
    assert len(calls) > 1  # had to split
    assert all(hi is not None or lo >= 10000 for lo, hi in calls)
    assert len(out) > 0


def test_count_commits_from_link_header():
    link = '<https://api.github.com/x?per_page=1&page=2>; rel="next", <https://api.github.com/x?per_page=1&page=4321>; rel="last"'
    assert dr.count_commits(lambda u: (200, {"link": link}, [{}]), "a/b") == 4321
    assert dr.count_commits(lambda u: (200, {}, [{}]), "a/b") == 1
    assert dr.count_commits(lambda u: (404, {}, None), "a/b") is None


def test_discover_filters():
    now = dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc)
    cands = [_item("a/good", 50000), _item("a/few", 20000), _item("a/solo", 15000),
             _item("a/arch", 30000, archived=True), _item("a/fork", 30000, fork=True),
             _item("a/small", 100)]
    counts = {"a/good": 500, "a/few": 40, "a/solo": 900}

    def fetch(url):
        name = "/".join(url.split("/repos/")[1].split("/")[:2])
        if "per_page=1" in url and "since" not in url:
            return 200, {"link": f'<u?page={counts[name]}>; rel="last"'}, [{}]
        authors = ["x", "y", "x"] if name != "a/solo" else ["x", "x"]
        return 200, {}, [{"author": {"login": a}} for a in authors]

    acc, st = dr.discover(fetch, candidates=cands, now=now)
    assert [r["owner_repo"] for r in acc] == ["a/good"]
    assert st["rejected_commits"] == 1 and st["rejected_committers"] == 1
    assert st["rejected_archived_or_fork"] == 3
    assert acc[0]["total_commits"] == 500


def test_ledger_resume_ignores_partial_line_and_retry(tmp_path):
    p = tmp_path / "l.jsonl"
    p.write_text(
        json.dumps({"owner_repo": "a/b", "status": "passed"}) + "\n"
        + json.dumps({"owner_repo": "a/c", "status": "timeout"}) + "\n"
        + '{"owner_repo": "a/d", "stat', encoding="utf-8")
    led = rs.load_ledger(p)
    assert set(led) == {"a/b", "a/c"}
    repos = [{"owner_repo": n} for n in ("a/b", "a/c", "a/d")]
    assert [r["owner_repo"] for r in rs.select_pending(repos, led)] == ["a/d"]
    assert [r["owner_repo"] for r in rs.select_pending(repos, led, True)] == ["a/c", "a/d"]


def test_classify():
    assert rs.classify({"overall_result": "passed"}) == "passed"
    assert rs.classify({"overall_result": "insufficient_history"}) == "insufficient_history"
    assert rs.classify({"overall_result": "failed"}) == "failed"


def test_report_numbers_are_from_ledger():
    recs = {
        "a/1": {"owner_repo": "a/1", "status": "passed", "primary_language": "Go", "commits_inspected": 100,
                "files_changed": 10, "breaking_changes_count": 2, "wall_seconds": 4.0,
                "evidence_integrity_status": "passed", "mode": "deterministic"},
        "a/2": {"owner_repo": "a/2", "status": "timeout", "primary_language": "Go", "wall_seconds": 600,
                "failure_reason": "exceeded 600s", "mode": "deterministic"},
    }
    s = ar.summarize(list(recs.values()))
    assert s["n"] == 2 and s["ok"] == 1 and s["breaking"] == 2 and s["commits_inspected"] == 100
    md = ar.render({"x.jsonl": recs})
    assert "| timeout | 1 (50.0%) |" in md and "| Repositories attempted | 2 |" in md
