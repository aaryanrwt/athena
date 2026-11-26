"""Persistent Zero-Dependency Token Savings Ledger (`athena gain`).

Tracks raw vs compacted output sizes across Athena commands (map, graph query,
retained summary views) using exact canonical path scoping immune to glob
wildcards and silent degradation on read-only environments.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from athena.security import redact_secrets

_LEDGER_LOCK = threading.Lock()


def estimate_tokens(chars: int) -> int:
    """Deterministic ~4-chars-per-token estimator matching repository budgets."""
    if chars <= 0:
        return 0
    return max(1, (chars + 3) // 4)


def _ledger_path() -> Path:
    override = os.environ.get("ATHENA_GAIN_LOG", "").strip()
    if override:
        return Path(override)
    return Path.home() / ".athena" / "gain.jsonl"


def _is_ledger_disabled() -> bool:
    return os.environ.get("ATHENA_GAIN_DISABLE", "").strip().lower() in {"1", "true", "yes", "on"}


def _canonical_project(project_path: str | Path) -> str:
    raw = str(project_path).strip() or "."
    try:
        return str(Path(raw).resolve())
    except OSError:
        return raw


def _project_matches(entry_project: str, filter_project: str) -> bool:
    if not filter_project:
        return True
    try:
        ep = Path(entry_project)
        fp = Path(filter_project)
        if os.name == "nt":
            e_norm = os.path.normcase(str(ep))
            f_norm = os.path.normcase(str(fp))
            if e_norm == f_norm:
                return True
            return Path(e_norm).is_relative_to(Path(f_norm))
        return ep == fp or ep.is_relative_to(fp)
    except (ValueError, OSError):
        return entry_project == filter_project


def record_token_saving(
    command: str,
    project_path: str | Path,
    raw_chars: int,
    emitted_chars: int,
    *,
    detail: str = "",
) -> dict[str, Any]:
    """Append one token-savings telemetry entry and degrade silently on read-only storage."""
    raw_c = max(0, int(raw_chars))
    emit_c = max(0, int(emitted_chars))
    saved_c = max(0, raw_c - emit_c)
    raw_tok = estimate_tokens(raw_c)
    emit_tok = estimate_tokens(emit_c)
    saved_tok = max(0, raw_tok - emit_tok)
    pct = round((saved_c / raw_c) * 100.0, 2) if raw_c > 0 else 0.0
    expanded = emit_c > raw_c
    entry: dict[str, Any] = {
        "timestamp": int(time.time()),
        "command": str(command),
        "project_path": _canonical_project(project_path),
        "raw_chars": raw_c,
        "emitted_chars": emit_c,
        "saved_chars": saved_c,
        "raw_tokens": raw_tok,
        "emitted_tokens": emit_tok,
        "tokens_saved": saved_tok,
        "savings_pct": pct,
        "expanded": expanded,
        "detail": redact_secrets(detail)[:120] if detail else "",
    }
    if _is_ledger_disabled():
        return entry

    dest = _ledger_path()
    try:
        if dest.is_symlink():
            return entry
        dest.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
        with _LEDGER_LOCK:
            with dest.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line)
    except OSError:
        # Read-only HOME / sandbox directories must never fail analysis commands.
        return entry
    return entry


def read_gain_report(
    project_path: str | Path | None = None,
    *,
    limit: int = 20,
) -> dict[str, Any]:
    """Read and aggregate historical token savings filtered safely by canonical project path."""
    dest = _ledger_path()
    scope_path = _canonical_project(project_path) if project_path is not None else None
    safe_limit = max(1, min(int(limit), 200))

    entries: list[dict[str, Any]] = []
    if dest.is_file() and not dest.is_symlink():
        try:
            for raw_line in dest.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    item = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if not isinstance(item, dict):
                    continue
                if scope_path is not None and not _project_matches(str(item.get("project_path", "")), scope_path):
                    continue
                entries.append(item)
        except OSError:
            entries = []

    total_raw_chars = sum(int(e.get("raw_chars", 0)) for e in entries)
    total_emit_chars = sum(int(e.get("emitted_chars", 0)) for e in entries)
    total_saved_chars = sum(max(0, int(e.get("raw_chars", 0)) - int(e.get("emitted_chars", 0))) for e in entries)
    total_raw_tok = sum(int(e.get("raw_tokens", estimate_tokens(int(e.get("raw_chars", 0))))) for e in entries)
    total_emit_tok = sum(int(e.get("emitted_tokens", estimate_tokens(int(e.get("emitted_chars", 0))))) for e in entries)
    total_saved_tok = max(0, total_raw_tok - total_emit_tok)
    avg_pct = round((total_saved_chars / total_raw_chars) * 100.0, 2) if total_raw_chars > 0 else 0.0
    expanded_count = sum(1 for e in entries if e.get("expanded"))

    by_cmd: dict[str, dict[str, Any]] = {}
    for e in entries:
        cmd = str(e.get("command", "unknown"))
        bucket = by_cmd.setdefault(
            cmd,
            {
                "invocations": 0,
                "raw_tokens": 0,
                "emitted_tokens": 0,
                "tokens_saved": 0,
            },
        )
        bucket["invocations"] += 1
        bucket["raw_tokens"] += int(e.get("raw_tokens", 0))
        bucket["emitted_tokens"] += int(e.get("emitted_tokens", 0))
        bucket["tokens_saved"] += int(e.get("tokens_saved", 0))

    for bucket in by_cmd.values():
        rt = bucket["raw_tokens"]
        bucket["avg_savings_pct"] = round((bucket["tokens_saved"] / rt) * 100.0, 2) if rt > 0 else 0.0

    return {
        "status": "ok",
        "ledger_path": str(dest),
        "project_filter": scope_path,
        "total_commands": len(entries),
        "total_raw_chars": total_raw_chars,
        "total_emitted_chars": total_emit_chars,
        "total_saved_chars": total_saved_chars,
        "estimated_raw_tokens": total_raw_tok,
        "estimated_emitted_tokens": total_emit_tok,
        "estimated_tokens_saved": total_saved_tok,
        "avg_savings_pct": avg_pct,
        "expanded_count": expanded_count,
        "by_command": by_cmd,
        "recent_entries": list(reversed(entries[-safe_limit:])),
    }


def reset_gain_ledger() -> dict[str, Any]:
    """Delete the persistent JSONL token ledger file if present and safe."""
    dest = _ledger_path()
    try:
        if dest.is_symlink():
            return {"status": "error", "error_code": "SYMLINK_BLOCKED", "error_message": f"Refusing symlink ledger: {dest}"}
        existed = dest.is_file()
        if existed:
            dest.unlink()
        return {"status": "ok", "ledger_path": str(dest), "cleared": existed}
    except OSError as exc:
        return {"status": "error", "error_code": "LEDGER_RESET_FAILED", "error_message": str(exc)}


def get_ledger_status() -> dict[str, Any]:
    """Return lightweight telemetry ledger readiness metadata for `athena doctor`."""
    dest = _ledger_path()
    parent_writable = False
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        parent_writable = os.access(dest.parent, os.W_OK)
    except OSError:
        parent_writable = False
    entry_count = 0
    if dest.is_file() and not dest.is_symlink():
        try:
            entry_count = sum(1 for ln in dest.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())
        except OSError:
            entry_count = 0
    return {
        "disabled_by_env": _is_ledger_disabled(),
        "ledger_path": str(dest),
        "writable": parent_writable,
        "recorded_entries": entry_count,
    }
