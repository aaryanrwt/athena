"""Generate a sleek self-hosted vector SVG Star History card from GitHub's Stargazers API."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime, timedelta
from html import escape
import json
import math
import os
from pathlib import Path
import sys
import urllib.request
import xml.etree.ElementTree as ET


_SVG_WIDTH = 880
_SVG_HEIGHT = 340
_PLOT_LEFT = 56.0
_PLOT_RIGHT = 846.0
_PLOT_TOP = 88.0
_PLOT_BOTTOM = 282.0
_FONT_FAMILY = (
    "ui-sans-serif, -apple-system, BlinkMacSystemFont, "
    "'Segoe UI', Helvetica, Arial, sans-serif"
)


def _github_get_json(url: str, accept: str, token: str | None) -> object:
    """Fetch and decode JSON from the GitHub REST API."""
    headers = {
        "User-Agent": "athena-star-history-generator",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_star_timeline(repo: str, token: str | None) -> tuple[date, list[date]]:
    """Return repository creation date and sorted list of real stargazer dates."""
    repo_meta = _github_get_json(
        f"https://api.github.com/repos/{repo}",
        accept="application/vnd.github+json",
        token=token,
    )
    if not isinstance(repo_meta, dict) or "created_at" not in repo_meta:
        raise RuntimeError(f"Unexpected repository metadata payload for {repo}")
    created_date = datetime.fromisoformat(repo_meta["created_at"].replace("Z", "+00:00")).date()

    star_dates: list[date] = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repo}/stargazers?per_page=100&page={page}"
        batch = _github_get_json(url, accept="application/vnd.github.star+json", token=token)
        if not isinstance(batch, list) or not batch:
            break
        for entry in batch:
            if isinstance(entry, dict) and entry.get("starred_at"):
                dt = datetime.fromisoformat(entry["starred_at"].replace("Z", "+00:00")).date()
                star_dates.append(dt)
        if len(batch) < 100:
            break
        page += 1

    star_dates.sort()
    return created_date, star_dates


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
    ticks = list(range(0, top + 1, step))
    return top, ticks


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


def render_svg(
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

    # Header right-aligned status pills (sized to text length cleanly)
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
            f'fill="#047857" font-family="{_FONT_FAMILY}" font-size="11.5" font-weight="600">'
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
            f'fill="#6D28D9" font-family="{_FONT_FAMILY}" font-size="11.5" font-weight="600">'
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
            f'fill="#64748B" font-family="{_FONT_FAMILY}" font-size="11" font-weight="500">{tick}</text>'
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
        label = day.strftime("%b %d").replace(" 0", " ")
        x_ticks_svg.append(
            f'  <text x="{tx:.2f}" y="{_PLOT_BOTTOM + 20:.0f}" text-anchor="{anchor}" '
            f'fill="#64748B" font-family="{_FONT_FAMILY}" font-size="11" font-weight="500">'
            f"{escape(label)}</text>"
        )

    # Endpoint callout badge positioned cleanly inside plot area without clipping
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
        "  <g clip-path=\"url(#cardClip)\">",
        f'    <rect x="0" y="0" width="{_SVG_WIDTH}" height="{_SVG_HEIGHT}" fill="#FFFFFF"/>',
        f'    <rect x="0" y="0" width="{_SVG_WIDTH}" height="3" fill="url(#lineGrad)"/>',
        "  </g>",
        f'  <rect x="0.75" y="0.75" width="{_SVG_WIDTH - 1.5:.2f}" height="{_SVG_HEIGHT - 1.5:.2f}" rx="16" fill="none" stroke="#CBD5E1" stroke-width="1.5"/>',
        "",
        f'  <text x="28" y="38" fill="#0F172A" font-family="{_FONT_FAMILY}" font-size="17" font-weight="700">Star History</text>',
        f'  <text x="28" y="57" fill="#64748B" font-family="{_FONT_FAMILY}" font-size="11.5" font-weight="500">{escape(repo)} · Live GitHub Stargazers</text>',
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
            f'fill="#FFFFFF" font-family="{_FONT_FAMILY}" font-size="10.5" font-weight="600">{escape(end_label)}</text>',
            "",
            f'  <text x="28" y="324" fill="#94A3B8" font-family="{_FONT_FAMILY}" font-size="10.5" font-weight="500">'
            f"Latest star: {escape(latest_str)} · Auto-updated via GitHub Actions</text>",
            "</svg>",
        ]
    )
    svg = "\n".join(lines) + "\n"
    ET.fromstring(svg)
    return svg


def _run_self_test() -> None:
    """Validate series builder, monotone spline overshoot bounds, and SVG XML validity."""
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
    assert total == len(sample_stars)
    assert delta_7d == 3
    assert latest == date(2026, 11, 24)
    assert series[0][1] == 0 and series[-1][1] == total

    y_max, _ = _nice_y_ticks(total)
    n = len(series)
    pts = [
        (_PLOT_LEFT + (i / (n - 1)) * (_PLOT_RIGHT - _PLOT_LEFT), _PLOT_BOTTOM - (v / y_max) * (_PLOT_BOTTOM - _PLOT_TOP))
        for i, (_, v) in enumerate(series)
    ]
    beziers = _monotone_cubic_beziers(pts)
    assert len(beziers) == n - 1
    for i, (cx1, cy1, cx2, cy2, x1, y1) in enumerate(beziers):
        x0, y0 = pts[i]
        lo, hi = min(y0, y1) - 1e-6, max(y0, y1) + 1e-6
        for step in range(21):
            t = step / 20.0
            mt = 1.0 - t
            by = (mt**3) * y0 + 3 * (mt**2) * t * cy1 + 3 * mt * (t**2) * cy2 + (t**3) * y1
            assert lo <= by <= hi, f"Monotone spline overshoot at seg {i}: {by} not in [{lo}, {hi}]"

    svg = render_svg("example/athena", series, total, delta_7d, latest)
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    assert "12 Stars" in svg and "+3 in 7d" in svg
    print("SELF_TEST_OK")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate modern SVG Star History chart.")
    parser.add_argument("--repo", default="aaryanrwt/athena", help="GitHub repository (owner/name)")
    parser.add_argument("--output", default="assets/star-history.svg", help="Output SVG path")
    parser.add_argument("--self-test", action="store_true", help="Run in-memory verification without writing files")
    args = parser.parse_args(argv)

    if args.self_test:
        _run_self_test()
        return 0

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    created_date, star_dates = fetch_star_timeline(args.repo, token)
    series, total_stars, last_7d_delta, latest_date = build_daily_series(created_date, star_dates)
    svg = render_svg(args.repo, series, total_stars, last_7d_delta, latest_date)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(svg, encoding="utf-8", newline="\n")
    print(f"Wrote {out_path} ({total_stars} stars, +{last_7d_delta} in 7d, latest {latest_date})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
