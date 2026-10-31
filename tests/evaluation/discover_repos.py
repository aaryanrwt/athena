"""Discover active, popular GitHub repositories and write a manifest JSON.

Criteria: stars >= --min-stars, pushed within --pushed-days, not archived, not a fork,
>= --min-commits commits, and >= --min-committers distinct recent committers.

The GitHub Search API caps each query at 1000 results, so the star range is split
adaptively (and by language as a last resort) until every shard fits under the cap.
Requires env GH_TOKEN for real runs (unauthenticated works only for a handful of calls).

Usage:
    python discover_repos.py --out manifest_scale.json [--max-repos 2000]
    python discover_repos.py --repos psf/requests pallets/click --out m.json   # explicit list
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

API = "https://api.github.com"
SEARCH_CAP = 1000
LANGUAGES = [
    "Python", "JavaScript", "TypeScript", "Go", "Rust", "Java", "C++", "C", "C#",
    "PHP", "Ruby", "Kotlin", "Swift", "Shell", "Dart", "Scala",
]

# fetch(url) -> (status, headers(dict lower-case keys), parsed_json)
Fetcher = Callable[[str], "tuple[int, dict[str, str], Any]"]


def make_fetcher(token: str | None, max_retries: int = 6) -> Fetcher:
    """HTTP fetcher with rate-limit aware backoff."""

    def fetch(url: str) -> tuple[int, dict[str, str], Any]:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "athena-eval"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for attempt in range(max_retries):
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    body = resp.read().decode("utf-8")
                    return resp.status, hdrs, json.loads(body) if body else None
            except urllib.error.HTTPError as e:
                hdrs = {k.lower(): v for k, v in e.headers.items()}
                if e.code in (403, 429):
                    wait = compute_backoff(hdrs, attempt)
                    print(f"  [rate-limit] HTTP {e.code}; sleeping {wait:.0f}s", file=sys.stderr)
                    time.sleep(wait)
                    continue
                if e.code in (500, 502, 503, 504):
                    time.sleep(2 ** attempt)
                    continue
                return e.code, hdrs, None
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(2 ** attempt)
        return 0, {}, None

    return fetch


def compute_backoff(headers: dict[str, str], attempt: int, now: float | None = None) -> float:
    """Seconds to wait after a 403/429 using Retry-After or X-RateLimit-Reset."""
    now = time.time() if now is None else now
    if "retry-after" in headers:
        try:
            return max(1.0, float(headers["retry-after"]) + 1)
        except ValueError:
            pass
    if headers.get("x-ratelimit-remaining") == "0" and "x-ratelimit-reset" in headers:
        try:
            return max(1.0, float(headers["x-ratelimit-reset"]) - now + 2)
        except ValueError:
            pass
    return float(min(120, 10 * (2 ** attempt)))


def build_query(lo: int, hi: int | None, pushed_since: str, language: str | None = None) -> str:
    stars = f"stars:{lo}..{hi}" if hi is not None else f"stars:>={lo}"
    q = f"{stars} pushed:>={pushed_since} archived:false fork:false"
    if language:
        q += f' language:"{language}"'
    return q


def _search(fetch: Fetcher, query: str, page: int) -> tuple[int, list[dict[str, Any]]]:
    url = f"{API}/search/repositories?{urllib.parse.urlencode({'q': query, 'sort': 'stars', 'order': 'desc', 'per_page': 100, 'page': page})}"
    status, _, data = fetch(url)
    if status != 200 or not data:
        return 0, []
    return int(data.get("total_count", 0)), data.get("items", [])


def shard_search(
    fetch: Fetcher,
    lo: int,
    hi: int | None,
    pushed_since: str,
    language: str | None = None,
    hard_hi: int = 2_000_000,
) -> list[dict[str, Any]]:
    """Recursively split the star range so each query returns <= 1000 results."""
    q = build_query(lo, hi, pushed_since, language)
    total, items = _search(fetch, q, 1)
    if total == 0:
        return []
    if total <= SEARCH_CAP:
        out = list(items)
        page = 2
        while len(out) < total and len(out) < SEARCH_CAP:
            _, more = _search(fetch, q, page)
            if not more:
                break
            out.extend(more)
            page += 1
        return out
    # Too many results: split.
    top = hi if hi is not None else hard_hi
    if top > lo:
        mid = (lo + top) // 2
        if hi is None:
            # open-ended: split into [lo, mid] and [mid+1, open]
            return shard_search(fetch, lo, mid, pushed_since, language) + shard_search(
                fetch, mid + 1, None, pushed_since, language
            ) if mid >= lo else []
        return shard_search(fetch, lo, mid, pushed_since, language) + shard_search(
            fetch, mid + 1, hi, pushed_since, language
        )
    if language is None:
        out: list[dict[str, Any]] = []
        for lang in LANGUAGES:
            out.extend(shard_search(fetch, lo, hi, pushed_since, lang))
        return out
    return list(items)  # cannot split further; keep what we got


def count_commits(fetch: Fetcher, full_name: str) -> int | None:
    """Total commit count via the Link header trick (per_page=1)."""
    status, headers, data = fetch(f"{API}/repos/{full_name}/commits?per_page=1")
    if status != 200:
        return None
    m = re.search(r'[?&]page=(\d+)>; rel="last"', headers.get("link", ""))
    if m:
        return int(m.group(1))
    return len(data) if isinstance(data, list) else None


def recent_committers(fetch: Fetcher, full_name: str, since: str) -> set[str]:
    status, _, data = fetch(f"{API}/repos/{full_name}/commits?since={since}&per_page=100")
    if status != 200 or not isinstance(data, list):
        return set()
    ids: set[str] = set()
    for c in data:
        author = c.get("author") or {}
        commit_author = (c.get("commit") or {}).get("author") or {}
        ident = author.get("login") or commit_author.get("email") or commit_author.get("name")
        if ident:
            ids.add(str(ident).lower())
    return ids


def to_manifest_entry(item: dict[str, Any], commits: int | None, committers: int) -> dict[str, Any]:
    full = item["full_name"]
    return {
        "owner_repo": full,
        "url": item.get("clone_url") or f"https://github.com/{full}.git",
        "primary_language": item.get("language") or "Unknown",
        "stars_at_collection": item.get("stargazers_count", 0),
        "license": ((item.get("license") or {}).get("spdx_id")) or "Unknown",
        "pushed_at": item.get("pushed_at"),
        "default_branch": item.get("default_branch"),
        "total_commits": commits,
        "recent_distinct_committers": committers,
        "selection_reason": "scale-discovery: stars/activity/commit filters",
    }


def discover(
    fetch: Fetcher,
    min_stars: int = 10000,
    pushed_days: int = 90,
    min_commits: int = 100,
    min_committers: int = 2,
    max_repos: int | None = None,
    candidates: list[dict[str, Any]] | None = None,
    now: dt.datetime | None = None,
    existing: dict[str, dict[str, Any]] | None = None,
    checkpoint: Callable[[list[dict[str, Any]]], None] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    now = now or dt.datetime.now(dt.timezone.utc)
    pushed_since = (now - dt.timedelta(days=pushed_days)).strftime("%Y-%m-%d")
    since_iso = (now - dt.timedelta(days=pushed_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = {"candidates": 0, "rejected_archived_or_fork": 0, "rejected_commits": 0,
             "rejected_committers": 0, "rejected_error": 0, "accepted": 0}
    if candidates is None:
        candidates = shard_search(fetch, min_stars, None, pushed_since)
    seen: set[str] = set()
    uniq = []
    for it in candidates:
        if it["full_name"] not in seen:
            seen.add(it["full_name"])
            uniq.append(it)
    uniq.sort(key=lambda i: i.get("stargazers_count", 0), reverse=True)
    stats["candidates"] = len(uniq)
    accepted: list[dict[str, Any]] = list((existing or {}).values())
    done = set((existing or {}).keys())
    for it in uniq:
        if max_repos and len(accepted) >= max_repos:
            break
        name = it["full_name"]
        if name in done:
            continue
        if it.get("archived") or it.get("fork") or it.get("stargazers_count", 0) < min_stars:
            stats["rejected_archived_or_fork"] += 1
            continue
        n = count_commits(fetch, name)
        if n is None:
            stats["rejected_error"] += 1
            continue
        if n < min_commits:
            stats["rejected_commits"] += 1
            continue
        people = recent_committers(fetch, name, since_iso)
        if len(people) < min_committers:
            stats["rejected_committers"] += 1
            continue
        accepted.append(to_manifest_entry(it, n, len(people)))
        stats["accepted"] += 1
        if checkpoint and stats["accepted"] % 25 == 0:
            checkpoint(accepted)
    return accepted, stats


def fetch_explicit(fetch: Fetcher, names: list[str]) -> list[dict[str, Any]]:
    out = []
    for n in names:
        status, _, data = fetch(f"{API}/repos/{n}")
        if status == 200 and data:
            out.append(data)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(Path(__file__).parent / "manifest_scale.json"))
    ap.add_argument("--min-stars", type=int, default=10000)
    ap.add_argument("--pushed-days", type=int, default=90)
    ap.add_argument("--min-commits", type=int, default=100)
    ap.add_argument("--min-committers", type=int, default=2)
    ap.add_argument("--max-repos", type=int, default=None)
    ap.add_argument("--repos", nargs="*", help="Explicit owner/name list (skips search; for testing).")
    ap.add_argument("--resume", action="store_true", help="Keep entries already in --out.")
    args = ap.parse_args()

    token = os.environ.get("GH_TOKEN")
    if not token:
        if not args.repos:
            print("ERROR: GH_TOKEN is required for full discovery (search rate limits).", file=sys.stderr)
            return 2
        print("WARNING: GH_TOKEN not set; unauthenticated (60 req/h). Use only for tiny runs.", file=sys.stderr)
    fetch = make_fetcher(token)
    out = Path(args.out)
    existing: dict[str, dict[str, Any]] = {}
    if args.resume and out.exists():
        existing = {r["owner_repo"]: r for r in json.loads(out.read_text(encoding="utf-8"))}

    def save(items: list[dict[str, Any]]) -> None:
        out.write_text(json.dumps(items, indent=2), encoding="utf-8")

    cands = fetch_explicit(fetch, args.repos) if args.repos else None
    accepted, stats = discover(
        fetch, args.min_stars, args.pushed_days, args.min_commits, args.min_committers,
        args.max_repos, cands, existing=existing, checkpoint=save,
    )
    save(accepted)
    print(json.dumps({"manifest": str(out), "total": len(accepted), **stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
