"""Automated README asset generator & badge health checker for Athena.

Generates self-hosted vector SVGs directly from GitHub's REST API:
  - <assets_dir>/star-history.svg
  - <assets_dir>/badges/release.svg
  - <assets_dir>/badges/stars.svg
  - <assets_dir>/badges/activity.svg
  - <assets_dir>/badges/license.svg

Zero third-party Python dependencies (standard library only).
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime, timedelta
from html import escape
import json
import math
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET


_SVG_WIDTH = 880
_SVG_HEIGHT = 340
_PLOT_LEFT = 56.0
_PLOT_RIGHT = 846.0
_PLOT_TOP = 88.0
_PLOT_BOTTOM = 282.0
_CHART_FONT = (
    "ui-sans-serif, -apple-system, BlinkMacSystemFont, "
    "'Segoe UI', Helvetica, Arial, sans-serif"
)
_BADGE_FONT = "Verdana, Geneva, 'DejaVu Sans', sans-serif"

# Clean vector icons (16x16 viewBox or normalized into 14x14 slot)
_ICON_GITHUB = (
    '<path fill="#E0E7FF" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59'
    '.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94'
    '-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82'
    '.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95'
    ' 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82'
    '.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82'
    '.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95'
    '.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38'
    'A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/>'
)
_ICON_STAR = (
    '<path fill="#E0E7FF" d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612'
    'a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.751.751 0 0 1-1.088.791'
    'L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374'
    'a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Z"/>'
)
_ICON_GIT_COMMIT = (
    '<path fill="#E0E7FF" d="M11.93 8.5a4.002 4.002 0 0 1-7.86 0H.75a.75.75 0 0 1 0-1.5'
    'h3.32a4.002 4.002 0 0 1 7.86 0h3.32a.75.75 0 0 1 0 1.5Zm-1.43-.75a2.5 2.5 0 1 0-5 0'
    ' 2.5 2.5 0 0 0 5 0Z"/>'
)
_ICON_LICENSE = (
    '<path fill="#E0E7FF" d="M8.75.75V2h.985c.304 0 .603.08.867.231l1.29.736'
    'c.038.022.08.033.124.033h2.234a.75.75 0 0 1 0 1.5h-.427l2.111 4.692'
    'a.75.75 0 0 1-.154.838l-.53-.53.529.531-.001.002-.002.002-.006.006-.006.005'
    '-.01.01-.045.04c-.21.176-.441.327-.686.45C14.556 10.78 13.88 11 13 11'
    'a4.498 4.498 0 0 1-2.023-.454 3.544 3.544 0 0 1-.686-.45l-.045-.04-.016-.015'
    '-.006-.006-.004-.004v-.001a.752.752 0 0 1-.154-.838L12.178 4.5h-.162'
    'c-.305 0-.604-.079-.868-.231l-1.29-.736a.245.245 0 0 0-.124-.033H8.75'
    'V13h2.5a.75.75 0 0 1 0 1.5h-6.5a.75.75 0 0 1 0-1.5h2.5V3.5h-.984'
    'a.245.245 0 0 0-.124.033l-1.29.736c-.264.152-.563.231-.868.231h-.162'
    'l2.112 4.692a.75.75 0 0 1-.154.838l-.53-.53.529.531-.001.002-.002.002'
    '-.006.006-.016.015-.045.04c-.21.176-.441.327-.686.45C4.556 10.78 3.88 11 3 11'
    'a4.498 4.498 0 0 1-2.023-.454 3.544 3.544 0 0 1-.686-.45l-.045-.04-.016-.015'
    '-.006-.006-.004-.004v-.001a.752.752 0 0 1-.154-.838L2.178 4.5H1.75'
    'a.75.75 0 0 1 0-1.5h2.234a.249.249 0 0 0 .125-.033l1.29-.736'
    'c.263-.15.561-.231.865-.231H7.25V.75a.75.75 0 0 1 1.5 0Zm2.945 8.477'
    'c.285.135.718.273 1.305.273s1.02-.138 1.305-.273L13 6.327l-1.305 2.9Z'
    'm-10 0c.285.135.718.273 1.305.273s1.02-.138 1.305-.273L3 6.327l-1.305 2.9Z"/>'
)


_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"), "[REDACTED]"),
    (
        re.compile(r"(Authorization\s*:\s*(?:Bearer|token)\s+)[^\s\"']+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(https?://)([^:@/\s]+):([^@/\s]+)@", re.IGNORECASE),
        r"\1[REDACTED]@",
    ),
    (
        re.compile(r"([?&](?:token|access_token|api_key|key)=)([^&\s]+)", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
)


def _redact_secrets(text: str, extra_secrets: tuple[str, ...] = ()) -> str:
    """Mask raw API tokens, Authorization headers, URL creds, and token query params."""
    masked = str(text)
    for secret in extra_secrets:
        if secret:
            masked = masked.replace(secret, "[REDACTED]")
    for pattern, replacement in _SECRET_PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked


def _safe_print(message: str, *, secrets: tuple[str, ...] = (), file: object = None) -> None:
    """Write stdout/stderr output only after scrubbing any active credentials."""
    stream = file if file is not None else sys.stdout
    print(_redact_secrets(message, secrets), file=stream)  # type: ignore[arg-type]


def _github_get_json(url: str, accept: str, token: str | None) -> object:
    """Fetch and decode JSON from the GitHub REST API with credential host pinning."""
    if not url.startswith("https://api.github.com/"):
        raise ValueError("Refusing to send GitHub API credentials to a non-GitHub API URL.")
    active_secrets = (token,) if token else ()
    headers = {
        "User-Agent": "athena-readme-bot",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise
        raise RuntimeError(_redact_secrets(f"GitHub API request failed ({url}): {exc}", active_secrets)) from None
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(_redact_secrets(f"GitHub API request failed ({url}): {exc}", active_secrets)) from None


def _is_bot_commit(entry: dict) -> bool:
    """Return True for automated workflow commits so activity date skips bot loops."""
    author = entry.get("author")
    if isinstance(author, dict) and author.get("login") == "github-actions[bot]":
        return True
    commit = entry.get("commit")
    if isinstance(commit, dict):
        c_author = commit.get("author") or {}
        if isinstance(c_author, dict) and c_author.get("name") == "github-actions[bot]":
            return True
        msg = str(commit.get("message") or "").lstrip()
        if msg.startswith(("chore(bot):", "chore(readme): update star history")):
            return True
    return False


def _format_short_date(d: date) -> str:
    return d.strftime("%b %d").replace(" 0", " ")


def fetch_repo_state(repo: str, token: str | None) -> dict[str, object]:
    """Fetch metadata, latest tag/release, latest human commit date, and star dates."""
    meta = _github_get_json(
        f"https://api.github.com/repos/{repo}",
        accept="application/vnd.github+json",
        token=token,
    )
    if not isinstance(meta, dict) or "created_at" not in meta:
        raise RuntimeError(f"Unexpected repository metadata payload for {repo}")

    created_date = datetime.fromisoformat(meta["created_at"].replace("Z", "+00:00")).date()

    spdx = "Apache-2.0"
    lic = meta.get("license")
    if isinstance(lic, dict) and lic.get("spdx_id") and lic["spdx_id"] != "NOASSERTION":
        spdx = str(lic["spdx_id"])

    # Latest release or tag
    latest_tag = "v0.0.0"
    try:
        rel = _github_get_json(
            f"https://api.github.com/repos/{repo}/releases/latest",
            accept="application/vnd.github+json",
            token=token,
        )
        if isinstance(rel, dict) and rel.get("tag_name"):
            latest_tag = str(rel["tag_name"])
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    if latest_tag == "v0.0.0":
        tags = _github_get_json(
            f"https://api.github.com/repos/{repo}/tags?per_page=10",
            accept="application/vnd.github+json",
            token=token,
        )
        if isinstance(tags, list) and tags and isinstance(tags[0], dict) and tags[0].get("name"):
            latest_tag = str(tags[0]["name"])

    # Latest non-bot commit date
    activity_date = created_date
    commits = _github_get_json(
        f"https://api.github.com/repos/{repo}/commits?per_page=20",
        accept="application/vnd.github+json",
        token=token,
    )
    if isinstance(commits, list) and commits:
        chosen = next((c for c in commits if isinstance(c, dict) and not _is_bot_commit(c)), commits[0])
        if isinstance(chosen, dict):
            commit_obj = chosen.get("commit") or {}
            date_iso = (
                (commit_obj.get("committer") or {}).get("date")
                or (commit_obj.get("author") or {}).get("date")
            )
            if date_iso:
                activity_date = datetime.fromisoformat(str(date_iso).replace("Z", "+00:00")).date()

    # Full stargazer timestamp history
    star_dates: list[date] = []
    page = 1
    while True:
        batch = _github_get_json(
            f"https://api.github.com/repos/{repo}/stargazers?per_page=100&page={page}",
            accept="application/vnd.github.star+json",
            token=token,
        )
        if not isinstance(batch, list) or not batch:
            break
        for entry in batch:
            if isinstance(entry, dict) and entry.get("starred_at"):
                dt = datetime.fromisoformat(str(entry["starred_at"]).replace("Z", "+00:00")).date()
                star_dates.append(dt)
        if len(batch) < 100:
            break
        page += 1
    star_dates.sort()

    total_stars = len(star_dates) if star_dates else int(meta.get("stargazers_count", 0))
    return {
        "created_date": created_date,
        "star_dates": star_dates,
        "total_stars": total_stars,
        "latest_tag": latest_tag,
        "activity_label": _format_short_date(activity_date),
        "license_spdx": spdx,
    }


def _estimate_text_width(text: str) -> float:
    """Estimate compact SVG pill width in px for 11px sans-serif text."""
    wide = set("MWmw@#%&")
    narrow = set("iljtI1.,:;!| ")
    width = 0.0
    for ch in text:
        if ch in wide:
            width += 8.6
        elif ch in narrow:
            width += 4.3
        elif ch.isupper():
            width += 7.4
        else:
            width += 6.6
    return width


def render_badge_svg(
    label: str,
    value: str,
    value_color: str,
    icon_markup: str | None = None,
    aria_label: str | None = None,
) -> str:
    """Render a crisp height=20 self-hosted vector SVG badge matching Athena's palette."""
    icon_pad = 18.0 if icon_markup else 0.0
    left_w = max(44.0, round(icon_pad + _estimate_text_width(label) + 14.0))
    right_w = max(36.0, round(_estimate_text_width(value) + 16.0))
    total_w = int(left_w + right_w)
    h = 20

    label_x = icon_pad + (left_w - icon_pad) / 2.0 + (2.0 if icon_markup else 0.0)
    value_x = left_w + right_w / 2.0
    accessible = aria_label or f"{label}: {value}"

    icon_block = ""
    if icon_markup:
        icon_block = f'\n  <g transform="translate(6, 3) scale(0.875)">{icon_markup}</g>'

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{h}" '
        f'viewBox="0 0 {total_w} {h}" role="img" aria-label="{escape(accessible)}">\n'
        f"  <title>{escape(accessible)}</title>\n"
        f"  <defs>\n"
        f'    <clipPath id="badgeClip"><rect width="{total_w}" height="{h}" rx="3"/></clipPath>\n'
        f"  </defs>\n"
        f'  <g clip-path="url(#badgeClip)">\n'
        f'    <rect width="{left_w:.0f}" height="{h}" fill="#111426"/>\n'
        f'    <rect x="{left_w:.0f}" width="{right_w:.0f}" height="{h}" fill="{escape(value_color)}"/>\n'
        f"  </g>{icon_block}\n"
        f'  <text x="{label_x:.1f}" y="13.8" text-anchor="middle" fill="#E0E7FF" '
        f'font-family="{_BADGE_FONT}" font-size="11" font-weight="500">{escape(label)}</text>\n'
        f'  <text x="{value_x:.1f}" y="13.8" text-anchor="middle" fill="#FFFFFF" '
        f'font-family="{_BADGE_FONT}" font-size="11" font-weight="600">{escape(value)}</text>\n'
        f"</svg>\n"
    )
    ET.fromstring(svg)
    return svg


def build_daily_series(
    created_date: date,
    star_dates: list[date],
) -> tuple[list[tuple[date, int]], int, int, date]:
    """Build cumulative daily star series anchored to the latest star date."""
    if not star_dates:
        return [(created_date, 0)], 0, 0, created_date

    per_day = Counter(star_dates)
    first_date = min(created_date, star_dates[0])
    latest_date = max(created_date, star_dates[-1])

    series: list[tuple[date, int]] = []
    if per_day.get(first_date, 0) > 0:
        series.append((first_date - timedelta(days=1), 0))

    running = 0
    cur = first_date
    while cur <= latest_date:
        running += per_day.get(cur, 0)
        series.append((cur, running))
        cur += timedelta(days=1)

    cutoff_7d = latest_date - timedelta(days=6)
    last_7d_delta = sum(count for day, count in per_day.items() if cutoff_7d <= day <= latest_date)
    return series, running, last_7d_delta, latest_date


def _nice_y_ticks(max_value: int) -> tuple[int, list[int]]:
    """Select clean integer Y-axis ticks capped at <= 5 intervals."""
    if max_value <= 0:
        return 5, [0, 1, 2, 3, 4, 5]

    magnitude = 1
    step = 1
    while True:
        found = False
        for mult in (1, 2, 5):
            candidate = mult * magnitude
            if math.ceil(max_value / candidate) <= 5:
                step = candidate
                found = True
                break
        if found:
            break
        magnitude *= 10

    top = max(step, math.ceil(max_value / step) * step)
    return top, list(range(0, top + 1, step))


def _monotone_cubic_beziers(
    points: list[tuple[float, float]],
) -> list[tuple[float, float, float, float, float, float]]:
    """Compute Fritsch-Carlson monotone cubic Bezier segments from sorted points."""
    n = len(points)
    if n < 2:
        return []
    if n == 2:
        (x0, y0), (x1, y1) = points
        return [(x0 + (x1 - x0) / 3.0, y0, x1 - (x1 - x0) / 3.0, y1, x1, y1)]

    hs = [points[k + 1][0] - points[k][0] for k in range(n - 1)]
    deltas = [
        (points[k + 1][1] - points[k][1]) / hs[k] if hs[k] > 0 else 0.0
        for k in range(n - 1)
    ]

    tangents = [0.0] * n
    tangents[0] = deltas[0]
    tangents[-1] = deltas[-1]
    for k in range(1, n - 1):
        d_prev, d_next = deltas[k - 1], deltas[k]
        if d_prev == 0.0 or d_next == 0.0 or (d_prev > 0.0) != (d_next > 0.0):
            tangents[k] = 0.0
        else:
            tangents[k] = 0.5 * (d_prev + d_next)

    for k in range(n - 1):
        dk = deltas[k]
        if dk == 0.0:
            tangents[k] = 0.0
            tangents[k + 1] = 0.0
            continue
        alpha = tangents[k] / dk
        beta = tangents[k + 1] / dk
        if alpha < 0.0:
            tangents[k] = 0.0
            alpha = 0.0
        if beta < 0.0:
            tangents[k + 1] = 0.0
            beta = 0.0
        sq = alpha * alpha + beta * beta
        if sq > 9.0:
            tau = 3.0 / math.sqrt(sq)
            tangents[k] = tau * alpha * dk
            tangents[k + 1] = tau * beta * dk

    segments: list[tuple[float, float, float, float, float, float]] = []
    for k in range(n - 1):
        x0, y0 = points[k]
        x1, y1 = points[k + 1]
        h = hs[k]
        cx1 = x0 + h / 3.0
        cy1 = y0 + (h / 3.0) * tangents[k]
        cx2 = x1 - h / 3.0
        cy2 = y1 - (h / 3.0) * tangents[k + 1]
        segments.append((cx1, cy1, cx2, cy2, x1, y1))
    return segments


def _select_x_tick_indices(total_points: int, target_ticks: int = 6) -> list[int]:
    """Select evenly spaced X-axis indices including start and end."""
    if total_points <= 1:
        return [0]
    if total_points <= target_ticks:
        return list(range(total_points))
    raw = [round(i * (total_points - 1) / (target_ticks - 1)) for i in range(target_ticks)]
    deduped: list[int] = []
    for idx in raw:
        if idx not in deduped:
            deduped.append(idx)
    if deduped[-1] != total_points - 1:
        deduped.append(total_points - 1)
    return deduped


def render_star_history_svg(
    repo: str,
    series: list[tuple[date, int]],
    total_stars: int,
    last_7d_delta: int,
    latest_date: date,
) -> str:
    """Render a crisp modern vector SVG Star History card."""
    y_max, y_ticks = _nice_y_ticks(total_stars)
    plot_w = _PLOT_RIGHT - _PLOT_LEFT
    plot_h = _PLOT_BOTTOM - _PLOT_TOP

    n = len(series)
    coords: list[tuple[float, float]] = []
    for idx, (_, val) in enumerate(series):
        x = _PLOT_LEFT if n == 1 else _PLOT_LEFT + (idx / (n - 1)) * plot_w
        y = _PLOT_BOTTOM - (val / y_max) * plot_h
        coords.append((round(x, 2), round(y, 2)))

    beziers = _monotone_cubic_beziers(coords)
    x_first, y_first = coords[0]
    x_last, y_last = coords[-1]

    if beziers:
        curve_cmds = [f"M {x_first:.2f} {y_first:.2f}"] + [
            f"C {cx1:.2f} {cy1:.2f}, {cx2:.2f} {cy2:.2f}, {x1:.2f} {y1:.2f}"
            for cx1, cy1, cx2, cy2, x1, y1 in beziers
        ]
        line_path = " ".join(curve_cmds)
        area_path = f"{line_path} L {x_last:.2f} {_PLOT_BOTTOM:.2f} L {x_first:.2f} {_PLOT_BOTTOM:.2f} Z"
    else:
        line_path = f"M {x_first:.2f} {y_first:.2f}"
        area_path = ""

    star_text = f"{total_stars} {'Star' if total_stars == 1 else 'Stars'}"
    star_pill_w = max(84, 34 + len(star_text) * 7)
    star_pill_x = 852 - star_pill_w
    star_pill_y = 22
    star_pill_h = 28

    badges_svg: list[str] = []
    if last_7d_delta > 0:
        delta_text = f"+{last_7d_delta} in 7d"
        delta_pill_w = max(72, 22 + len(delta_text) * 6.5)
        delta_pill_x = star_pill_x - 10 - delta_pill_w
        badges_svg.append(
            f'  <rect x="{delta_pill_x:.1f}" y="{star_pill_y}" width="{delta_pill_w:.1f}" '
            f'height="{star_pill_h}" rx="14" fill="#ECFDF5" stroke="#A7F3D0" stroke-width="1"/>'
        )
        badges_svg.append(
            f'  <text x="{delta_pill_x + delta_pill_w / 2:.1f}" y="40" text-anchor="middle" '
            f'fill="#047857" font-family="{_CHART_FONT}" font-size="11.5" font-weight="600">'
            f"{escape(delta_text)}</text>"
        )

    badges_svg.extend(
        [
            f'  <rect x="{star_pill_x:.1f}" y="{star_pill_y}" width="{star_pill_w:.1f}" '
            f'height="{star_pill_h}" rx="14" fill="#F5F3FF" stroke="#DDD6FE" stroke-width="1"/>',
            f'  <g transform="translate({star_pill_x + 11:.1f}, 29) scale(0.58)" fill="#7C3AED">',
            '    <path d="M12 2l2.9 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l7.1-1.01L12 2z"/>',
            "  </g>",
            f'  <text x="{star_pill_x + 28 + (star_pill_w - 34) / 2:.1f}" y="40" text-anchor="middle" '
            f'fill="#6D28D9" font-family="{_CHART_FONT}" font-size="11.5" font-weight="600">'
            f"{escape(star_text)}</text>",
        ]
    )

    grid_svg: list[str] = []
    for tick in y_ticks:
        ty = _PLOT_BOTTOM - (tick / y_max) * plot_h
        is_base = tick == 0
        stroke = "#CBD5E1" if is_base else "#E2E8F0"
        dash = "" if is_base else ' stroke-dasharray="4 4"'
        grid_svg.append(
            f'  <line x1="{_PLOT_LEFT:.0f}" y1="{ty:.2f}" x2="{_PLOT_RIGHT:.0f}" y2="{ty:.2f}" '
            f'stroke="{stroke}" stroke-width="1"{dash}/>'
        )
        grid_svg.append(
            f'  <text x="{_PLOT_LEFT - 10:.0f}" y="{ty + 4:.2f}" text-anchor="end" '
            f'fill="#64748B" font-family="{_CHART_FONT}" font-size="11" font-weight="500">{tick}</text>'
        )

    x_ticks_svg: list[str] = []
    for idx in _select_x_tick_indices(n):
        day = series[idx][0]
        tx = coords[idx][0]
        anchor = "middle"
        if idx == 0:
            anchor = "start"
        elif idx == n - 1:
            anchor = "end"
        x_ticks_svg.append(
            f'  <text x="{tx:.2f}" y="{_PLOT_BOTTOM + 20:.0f}" text-anchor="{anchor}" '
            f'fill="#64748B" font-family="{_CHART_FONT}" font-size="11" font-weight="500">'
            f"{escape(_format_short_date(day))}</text>"
        )

    end_label = str(total_stars)
    end_label_w = max(24, 12 + len(end_label) * 7)
    end_badge_x = min(x_last - end_label_w / 2.0, _PLOT_RIGHT - end_label_w - 2)
    end_badge_y = y_last - 28.0 if y_last > _PLOT_TOP + 24 else y_last + 12.0

    latest_str = latest_date.strftime("%b %d, %Y").replace(" 0", " ")
    aria = f"{repo} Star History: {total_stars} stars through {latest_str}"

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_SVG_WIDTH}" height="{_SVG_HEIGHT}" '
        f'viewBox="0 0 {_SVG_WIDTH} {_SVG_HEIGHT}" role="img" aria-label="{escape(aria)}">',
        "  <defs>",
        f'    <clipPath id="cardClip"><rect x="0.75" y="0.75" width="{_SVG_WIDTH - 1.5:.2f}" height="{_SVG_HEIGHT - 1.5:.2f}" rx="16"/></clipPath>',
        '    <linearGradient id="lineGrad" x1="0%" y1="0%" x2="100%" y2="0%">',
        '      <stop offset="0%" stop-color="#6366F1"/>',
        '      <stop offset="52%" stop-color="#8B5CF6"/>',
        '      <stop offset="100%" stop-color="#06B6D4"/>',
        "    </linearGradient>",
        '    <linearGradient id="areaGrad" x1="0%" y1="0%" x2="0%" y2="100%">',
        '      <stop offset="0%" stop-color="#8B5CF6" stop-opacity="0.18"/>',
        '      <stop offset="100%" stop-color="#06B6D4" stop-opacity="0.01"/>',
        "    </linearGradient>",
        "  </defs>",
        "",
        '  <g clip-path="url(#cardClip)">',
        f'    <rect x="0" y="0" width="{_SVG_WIDTH}" height="{_SVG_HEIGHT}" fill="#FFFFFF"/>',
        f'    <rect x="0" y="0" width="{_SVG_WIDTH}" height="3" fill="url(#lineGrad)"/>',
        "  </g>",
        f'  <rect x="0.75" y="0.75" width="{_SVG_WIDTH - 1.5:.2f}" height="{_SVG_HEIGHT - 1.5:.2f}" rx="16" fill="none" stroke="#CBD5E1" stroke-width="1.5"/>',
        "",
        f'  <text x="28" y="38" fill="#0F172A" font-family="{_CHART_FONT}" font-size="17" font-weight="700">Star History</text>',
        f'  <text x="28" y="57" fill="#64748B" font-family="{_CHART_FONT}" font-size="11.5" font-weight="500">{escape(repo)} · Live GitHub Stargazers</text>',
        *badges_svg,
        "",
        *grid_svg,
        *x_ticks_svg,
        "",
    ]

    if area_path:
        lines.append(f'  <path d="{area_path}" fill="url(#areaGrad)"/>')
    lines.extend(
        [
            f'  <path d="{line_path}" fill="none" stroke="url(#lineGrad)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>',
            f'  <circle cx="{x_last:.2f}" cy="{y_last:.2f}" r="9" fill="#06B6D4" opacity="0.18"/>',
            f'  <circle cx="{x_last:.2f}" cy="{y_last:.2f}" r="4.5" fill="#06B6D4" stroke="#FFFFFF" stroke-width="2"/>',
            f'  <rect x="{end_badge_x:.1f}" y="{end_badge_y:.1f}" width="{end_label_w:.1f}" height="20" rx="6" fill="#0F172A"/>',
            f'  <text x="{end_badge_x + end_label_w / 2:.1f}" y="{end_badge_y + 13.5:.1f}" text-anchor="middle" '
            f'fill="#FFFFFF" font-family="{_CHART_FONT}" font-size="10.5" font-weight="600">{escape(end_label)}</text>',
            "",
            f'  <text x="28" y="324" fill="#94A3B8" font-family="{_CHART_FONT}" font-size="10.5" font-weight="500">'
            f"Latest star: {escape(latest_str)} · Auto-updated via GitHub Actions</text>",
            "</svg>",
        ]
    )
    svg = "\n".join(lines) + "\n"
    ET.fromstring(svg)
    return svg


def check_external_badges(
    readme_path: Path,
    active_secrets: tuple[str, ...] = (),
) -> list[tuple[str, str, str]]:
    """Health-check external https:// img tags in README.md without aborting on blips."""
    if not readme_path.exists():
        return []
    text = readme_path.read_text(encoding="utf-8")
    results: list[tuple[str, str, str]] = []
    for tag in re.findall(r"<img\b[^>]+>", text):
        src_m = re.search(r'src="(https?://[^"]+)"', tag)
        if not src_m:
            continue
        alt_m = re.search(r'alt="([^"]*)"', tag)
        alt = alt_m.group(1) if alt_m else "External image"
        url = src_m.group(1)
        safe_url = _redact_secrets(url, active_secrets)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "athena-readme-bot"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
                if resp.status == 200 and len(data) > 50:
                    results.append((alt, safe_url, f"HTTP 200 ({len(data)} bytes)"))
                else:
                    results.append((alt, safe_url, f"WARN HTTP {resp.status} ({len(data)} bytes)"))
        except Exception as exc:
            safe_err = _redact_secrets(str(exc), active_secrets)
            results.append((alt, safe_url, f"WARN {safe_err}"))
    return results


def _write_summary(
    generated: list[tuple[Path, str]],
    external_checks: list[tuple[str, str, str]],
    active_secrets: tuple[str, ...] = (),
) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    lines = [
        "## Athena README Badge & Star-History Bot",
        "",
        "| Asset | Status |",
        "| :--- | :--- |",
    ]
    for path, detail in generated:
        lines.append(f"| `{path.as_posix()}` | {detail} |")
    for alt, url, status in external_checks:
        lines.append(f"| External `{alt}` (`{url[:60]}`) | {status} |")
    with open(summary_file, "a", encoding="utf-8") as fh:
        fh.write(_redact_secrets("\n".join(lines) + "\n", active_secrets))


def _run_self_test() -> None:
    """Validate badge SVGs, monotone spline bounds, and XML validity in memory."""
    badges = {
        "release": render_badge_svg("release", "v1.3.2", "#818CF8", _ICON_GITHUB),
        "stars": render_badge_svg("stars", "21", "#A855F7", _ICON_STAR),
        "activity": render_badge_svg("updated", "Nov 24", "#0EA5E9", _ICON_GIT_COMMIT),
        "license": render_badge_svg("license", "Apache-2.0", "#6366F1", _ICON_LICENSE),
    }
    for name, svg in badges.items():
        root = ET.fromstring(svg)
        assert root.attrib["height"] == "20", f"{name} unexpected height"

    assert _is_bot_commit({"author": {"login": "github-actions[bot]"}, "commit": {"message": "x"}})
    assert _is_bot_commit({"author": None, "commit": {"message": "chore(bot): update README badges"}})
    assert not _is_bot_commit({"author": {"login": "aaryanrwt"}, "commit": {"message": "feat: add CLI"}})

    sample_secret = "custom_raw_token_value_123"
    dirty = (
        f"{sample_secret} "
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 "
        "github_pat_1234567890abcdefghij123456 "
        "Authorization: Bearer top_secret_bearer "
        "https://user:pass@example.com/a?token=leak123&x=1"
    )
    cleaned = _redact_secrets(dirty, (sample_secret,))
    for forbidden in (
        sample_secret,
        "ghp_",
        "github_pat_",
        "top_secret_bearer",
        "user:pass",
        "leak123",
    ):
        assert forbidden not in cleaned, f"Unredacted secret fragment: {forbidden}"

    try:
        _github_get_json("https://example.com/repos", "application/json", "ghp_1234567890abcdef1234")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for non-GitHub API URL")

    created = date(2026, 10, 16)
    sample_stars = [
        date(2026, 10, 18),
        date(2026, 10, 19),
        date(2026, 10, 21),
        date(2026, 10, 21),
        date(2026, 10, 25),
        date(2026, 10, 28),
        date(2026, 11, 2),
        date(2026, 11, 2),
        date(2026, 11, 2),
        date(2026, 11, 20),
        date(2026, 11, 22),
        date(2026, 11, 24),
    ]
    series, total, delta_7d, latest = build_daily_series(created, sample_stars)
    assert total == 12 and delta_7d == 3 and latest == date(2026, 11, 24)

    y_max, _ = _nice_y_ticks(total)
    n = len(series)
    pts = [
        (_PLOT_LEFT + (i / (n - 1)) * (_PLOT_RIGHT - _PLOT_LEFT), _PLOT_BOTTOM - (v / y_max) * (_PLOT_BOTTOM - _PLOT_TOP))
        for i, (_, v) in enumerate(series)
    ]
    beziers = _monotone_cubic_beziers(pts)
    for i, (_, cy1, _, cy2, _, y1) in enumerate(beziers):
        y0 = pts[i][1]
        lo, hi = min(y0, y1) - 1e-6, max(y0, y1) + 1e-6
        for step in range(21):
            t = step / 20.0
            mt = 1.0 - t
            by = (mt**3) * y0 + 3 * (mt**2) * t * cy1 + 3 * mt * (t**2) * cy2 + (t**3) * y1
            assert lo <= by <= hi, f"Monotone spline overshoot at segment {i}: {by}"

    chart_svg = render_star_history_svg("example/athena", series, total, delta_7d, latest)
    ET.fromstring(chart_svg)
    assert "12 Stars" in chart_svg and "+3 in 7d" in chart_svg
    print("SELF_TEST_OK")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Update Athena self-hosted README badges & Star History.")
    parser.add_argument("--repo", default="aaryanrwt/athena", help="GitHub repository (owner/name)")
    parser.add_argument("--assets-dir", default="assets", help="Target assets directory")
    parser.add_argument("--readme", default="README.md", help="README path for external badge checks")
    parser.add_argument("--check-external", action="store_true", help="Probe external badge URLs in README")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory checks without writing files")
    args = parser.parse_args(argv)

    if args.self_test:
        _run_self_test()
        return 0

    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip() or None
    active_secrets = (token,) if token else ()
    try:
        state = fetch_repo_state(args.repo, token)
    except Exception as exc:
        _safe_print(f"Error updating README assets: {exc}", secrets=active_secrets, file=sys.stderr)
        return 1

    created_date = state["created_date"]
    star_dates = state["star_dates"]
    series, series_stars, last_7d_delta, latest_date = build_daily_series(created_date, star_dates)  # type: ignore[arg-type]
    total_stars = int(state["total_stars"]) if not star_dates else series_stars

    assets_dir = Path(args.assets_dir)
    badges_dir = assets_dir / "badges"
    badges_dir.mkdir(parents=True, exist_ok=True)

    outputs: list[tuple[Path, str, str]] = [
        (
            assets_dir / "star-history.svg",
            render_star_history_svg(args.repo, series, total_stars, last_7d_delta, latest_date),
            f"{total_stars} stars (+{last_7d_delta} in 7d, latest {latest_date})",
        ),
        (
            badges_dir / "release.svg",
            render_badge_svg("release", str(state["latest_tag"]), "#818CF8", _ICON_GITHUB),
            f"release: {state['latest_tag']}",
        ),
        (
            badges_dir / "stars.svg",
            render_badge_svg("stars", str(total_stars), "#A855F7", _ICON_STAR),
            f"stars: {total_stars}",
        ),
        (
            badges_dir / "activity.svg",
            render_badge_svg("updated", str(state["activity_label"]), "#0EA5E9", _ICON_GIT_COMMIT),
            f"updated: {state['activity_label']}",
        ),
        (
            badges_dir / "license.svg",
            render_badge_svg("license", str(state["license_spdx"]), "#6366F1", _ICON_LICENSE),
            f"license: {state['license_spdx']}",
        ),
    ]

    summary_rows: list[tuple[Path, str]] = []
    for path, content, detail in outputs:
        path.write_text(content, encoding="utf-8", newline="\n")
        _safe_print(f"Wrote {path} ({detail})", secrets=active_secrets)
        summary_rows.append((path, detail))

    external_checks: list[tuple[str, str, str]] = []
    if args.check_external:
        external_checks = check_external_badges(Path(args.readme), active_secrets=active_secrets)
        for alt, url, status in external_checks:
            _safe_print(f"External check | {alt:28s} | {status}", secrets=active_secrets)

    _write_summary(summary_rows, external_checks, active_secrets=active_secrets)
    return 0


if __name__ == "__main__":
    sys.exit(main())
