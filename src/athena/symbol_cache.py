"""Opt-in, content-addressed on-disk cache for parsed symbol tables.

Entries are keyed by a SHA-256 digest of the file content (plus parser kind, file path,
extra parser inputs, and the Athena version), so a changed file can never hit a stale entry.
File names are always ``<64 hex chars>.json`` inside a single cache directory, which makes
path traversal through the key impossible. Any unreadable, oversized, malformed, or
mismatching entry is treated as a cache miss and never raises.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from athena import __version__
from athena.security import AthenaValidationError, WINDOWS_RESERVED_NAMES, write_text_safely

CACHE_SCHEMA_VERSION = 1
MAX_CACHE_ENTRY_BYTES = 8 * 1024 * 1024
_KEY_RE = re.compile(r"^[0-9a-f]{64}$")


def validate_cache_dir(raw: str | os.PathLike[str]) -> Path:
    """Validate and canonicalize an explicit cache directory (created on demand)."""
    text = str(raw).strip()
    if not text or "\x00" in text:
        raise AthenaValidationError("INVALID_CACHE_DIR", "Cache directory path is invalid.")
    candidate = Path(text).expanduser()
    for part in candidate.parts:
        if part.lower() == ".git":
            raise AthenaValidationError(
                "GIT_METADATA_WRITE_BLOCKED", f"Refusing to use a cache directory inside Git metadata: {text}"
            )
        if Path(part).stem.upper() in WINDOWS_RESERVED_NAMES:
            raise AthenaValidationError(
                "RESERVED_DEVICE_NAME_BLOCKED", f"Cache directory uses a reserved device name: {text}"
            )
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AthenaValidationError("INVALID_CACHE_DIR", f"Cache directory could not be resolved: {text}") from exc
    if resolved.exists() and not resolved.is_dir():
        raise AthenaValidationError("INVALID_CACHE_DIR", f"Cache path is not a directory: {resolved}")
    return resolved


def compute_cache_key(kind: str, file_path: str, source: str, extra: str = "") -> str:
    """Return the hex digest identifying one parse request."""
    digest = hashlib.sha256()
    for part in (str(CACHE_SCHEMA_VERSION), __version__, kind, file_path, extra):
        digest.update(part.encode("utf-8", errors="replace"))
        digest.update(b"\x00")
    digest.update(source.encode("utf-8", errors="replace"))
    return digest.hexdigest()


class SymbolCache:
    """JSON file cache living in one explicit directory."""

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self.directory = validate_cache_dir(directory)
        self.hits = 0
        self.misses = 0

    def _entry_path(self, key: str) -> Path | None:
        if not _KEY_RE.match(key):
            return None
        return self.directory / f"{key}.json"

    def get(self, key: str) -> Any | None:
        path = self._entry_path(key)
        if path is None:
            return None
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CACHE_ENTRY_BYTES:
                self.misses += 1
                return None
            envelope = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(envelope, dict)
                or envelope.get("schema") != CACHE_SCHEMA_VERSION
                or envelope.get("key") != key
                or "data" not in envelope
            ):
                self.misses += 1
                return None
        except (OSError, ValueError, RecursionError, UnicodeError):
            self.misses += 1
            return None
        self.hits += 1
        return envelope["data"]

    def put(self, key: str, data: Any) -> bool:
        path = self._entry_path(key)
        if path is None:
            return False
        try:
            payload = json.dumps({"schema": CACHE_SCHEMA_VERSION, "key": key, "data": data}, sort_keys=True)
            if len(payload) > MAX_CACHE_ENTRY_BYTES:
                return False
            write_text_safely(path, payload, overwrite=True)
            return True
        except (OSError, TypeError, ValueError, AthenaValidationError):
            return False


_ACTIVE_CACHE: SymbolCache | None = None


def configure_cache(directory: str | os.PathLike[str] | None) -> SymbolCache | None:
    """Enable the process-wide cache for ``directory`` or disable it with ``None``."""
    global _ACTIVE_CACHE
    _ACTIVE_CACHE = SymbolCache(directory) if directory else None
    return _ACTIVE_CACHE


def get_active_cache() -> SymbolCache | None:
    return _ACTIVE_CACHE
