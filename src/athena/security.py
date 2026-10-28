"""Security boundaries, path & revision validators, secret redaction, and prompt-injection fencing."""

from __future__ import annotations

import math
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel


class AthenaValidationError(ValueError):
    """Raised when a user-supplied path, revision, or parameter violates security boundaries."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# Strict revision regex: allows branch/tag names, SHAs, ~, ^, /, -, _, ., and + (SemVer build metadata)
# Explicitly forbids leading '-', whitespace, control characters, '..', and '@{'
_VALID_GIT_REF_RE = re.compile(r"^[A-Za-z0-9_.\-/~^+]{1,255}$")

WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

# Provider token & secret patterns (incorporating pr-agent#4079 bare token patterns)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "URI_USERINFO_CREDENTIAL",
        re.compile(
            r"(?i)\b(?P<scheme>https?|ftp)://(?P<username>[^\s/@:]+):(?P<password>[^\s/@]+)@"
        ),
    ),
    (
        "AUTHORIZATION_CREDENTIAL",
        re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
    ),
    ("GITHUB_PAT", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b")),
    ("GITHUB_FINE_PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{35,255}\b")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,255}\b")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9\-_]{20,255}\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIzaSy[A-Za-z0-9\-_]{33}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,255}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
    ),
    (
        "GENERIC_SECRET_ASSIGNMENT",
        re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)\s*[:=]\s*['\"]([^'\"]{8,120})['\"]"
        ),
    ),
]

_QUOTED_LITERAL_RE = re.compile(r"(['\"])([A-Za-z0-9+/=_\-]{28,128})\1")


def validate_repo_path(repo_path: str | Path) -> Path:
    """Validate and canonicalize a local directory path, handling Windows paths safely."""
    if not repo_path or not str(repo_path).strip():
        raise AthenaValidationError("EMPTY_REPO_PATH", "Repository path must not be empty.")
    raw_str = str(repo_path).strip()
    if "\x00" in raw_str:
        raise AthenaValidationError("NULL_BYTE_IN_PATH", "Repository path contains null bytes.")
    try:
        resolved = Path(raw_str).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AthenaValidationError(
            "REPO_PATH_NOT_FOUND",
            f"Repository path does not exist or cannot be resolved: {raw_str}",
        ) from exc

    if not resolved.is_dir():
        raise AthenaValidationError(
            "REPO_PATH_NOT_DIRECTORY",
            f"Path is not a directory: {resolved}",
        )
    return resolved


def validate_git_revision(rev: str | None, param_name: str = "revision") -> str:
    """Validate a Git revision reference to prevent Git CLI argument/option injection (flags starting with '-')."""
    if rev is None or not str(rev).strip():
        raise AthenaValidationError(
            "INVALID_GIT_REVISION",
            f"Parameter '{param_name}' must not be empty.",
        )
    cleaned = str(rev).strip()
    if cleaned in ("WORKING_TREE", "AUTO"):
        return cleaned
    if cleaned.startswith("-"):
        raise AthenaValidationError(
            "GIT_FLAG_INJECTION_BLOCKED",
            f"Parameter '{param_name}' ('{cleaned}') must not start with '-' (flag injection guard).",
        )
    if ".." in cleaned or "@{" in cleaned or "\\" in cleaned or "\x00" in cleaned:
        raise AthenaValidationError(
            "INVALID_GIT_REVISION",
            f"Parameter '{param_name}' ('{cleaned}') contains disallowed range or reflog syntax.",
        )
    if not _VALID_GIT_REF_RE.match(cleaned):
        raise AthenaValidationError(
            "INVALID_GIT_REVISION",
            f"Parameter '{param_name}' ('{cleaned}') contains invalid characters.",
        )
    return cleaned


def is_safe_repo_file(repo_root: Path, candidate_path: Path) -> bool:
    """Ensure a file is strictly inside repo_root and does not escape via path traversal or symlinks."""
    try:
        resolved_root = repo_root.resolve(strict=True)
        resolved_candidate = candidate_path.resolve(strict=True)
        return resolved_candidate.is_relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        return False


def validate_safe_output_path(
    repo_root: Path,
    output_path: str | Path,
    overwrite: bool = False,
) -> Path:
    """Validate an output Markdown path, ensuring it stays within repo_root and never overwrites silently."""
    raw = str(output_path).strip()
    if not raw or "\x00" in raw:
        raise AthenaValidationError("INVALID_OUTPUT_PATH", "Output file path is invalid.")
    # Block NTFS Alternate Data Streams (colon in non-drive-letter positions)
    clean_raw = raw.replace("\\", "/")
    has_drive_letter = len(clean_raw) >= 2 and clean_raw[1] == ":" and clean_raw[0].isalpha()
    sub_path = clean_raw[2:] if has_drive_letter else clean_raw
    if ":" in sub_path:
        raise AthenaValidationError(
            "NTFS_ADS_BLOCKED",
            f"Output file path contains NTFS Alternate Data Stream separator ':': {raw}",
        )

    candidate = Path(raw)
    if any(part.lower() == ".git" for part in candidate.parts):
        raise AthenaValidationError(
            "GIT_METADATA_WRITE_BLOCKED",
            f"Refusing to write release output inside Git metadata: {raw}",
        )
    # Check Windows reserved device names across all components
    for part in candidate.parts:
        part_clean = part.split(":")[0]  # strip any colon
        part_stem = Path(part_clean).stem.upper()
        part_name = Path(part_clean).name.upper()
        if part_stem in WINDOWS_RESERVED_NAMES or part_name in WINDOWS_RESERVED_NAMES:
            raise AthenaValidationError(
                "RESERVED_DEVICE_NAME_BLOCKED",
                f"Refusing to write file to Windows reserved device name '{part}': {raw}",
            )

    if not candidate.is_absolute():
        candidate = repo_root / candidate
    try:
        resolved_root = repo_root.resolve(strict=True)
        resolved_target = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AthenaValidationError(
            "INVALID_OUTPUT_PATH",
            f"Output path could not be resolved: {candidate}",
        ) from exc

    if not resolved_target.is_relative_to(resolved_root) or resolved_target == resolved_root:
        raise AthenaValidationError(
            "OUTPUT_PATH_ESCAPE_BLOCKED",
            f"Refusing to write file outside repository root ({resolved_root}): {candidate}",
        )
    git_metadata = resolved_root / ".git"
    if git_metadata.is_dir() and resolved_target.is_relative_to(git_metadata.resolve(strict=True)):
        raise AthenaValidationError(
            "GIT_METADATA_WRITE_BLOCKED",
            f"Refusing to write release output inside Git metadata: {candidate}",
        )
    if resolved_target.exists() and not overwrite:
        raise AthenaValidationError(
            "FILE_EXISTS_OVERWRITE_DENIED",
            f"Target file '{resolved_target}' already exists. Pass overwrite=True only after explicit user confirmation.",
        )
    return resolved_target


def write_text_safely(target: Path, content: str, overwrite: bool = False) -> None:
    """Write UTF-8 text without overwrite races or hard-link mutation."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if not overwrite:
        try:
            with target.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            return
        except FileExistsError as exc:
            raise AthenaValidationError(
                "FILE_EXISTS_OVERWRITE_DENIED",
                f"Target file '{target}' already exists. Pass overwrite=True only after explicit user confirmation.",
            ) from exc

    # Replacing a same-directory temporary file changes the directory entry instead
    # of mutating an existing hard-linked inode. A hostile process with write access
    # to the same parent directory can still race directory changes; Athena cannot
    # fully prevent that OS-level threat without platform-specific directory handles.
    tmp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as handle:
            tmp_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
        tmp_name = None
    finally:
        if tmp_name is not None:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError:
                pass


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact_secrets(text: str) -> str:
    """Scrub API keys, tokens, private keys, and high-entropy credentials from diffs/snippets."""
    if not text:
        return ""
    redacted = text
    for label, pattern in _SECRET_PATTERNS:
        if label == "GENERIC_SECRET_ASSIGNMENT":
            redacted = pattern.sub(r"\1 = '[REDACTED_SECRET]'", redacted)
        elif label == "AUTHORIZATION_CREDENTIAL":
            redacted = pattern.sub(r"\1[REDACTED_AUTHORIZATION_CREDENTIAL]", redacted)
        elif label == "URI_USERINFO_CREDENTIAL":
            redacted = pattern.sub(
                r"\g<scheme>://\g<username>:[REDACTED_URI_CREDENTIAL]@",
                redacted,
            )
        else:
            redacted = pattern.sub(f"[REDACTED_{label}]", redacted)

    def _entropy_replacer(match: re.Match[str]) -> str:
        quote = match.group(1)
        candidate = match.group(2)
        if "/" in candidate or "." in candidate or candidate.isalpha() or candidate.isdigit():
            return match.group(0)
        has_upper = any(c.isupper() for c in candidate)
        has_lower = any(c.islower() for c in candidate)
        has_digit = any(c.isdigit() for c in candidate)
        if has_upper and has_lower and has_digit and shannon_entropy(candidate) > 4.5:
            return f"{quote}[REDACTED_HIGH_ENTROPY_SECRET]{quote}"
        return match.group(0)

    return _QUOTED_LITERAL_RE.sub(_entropy_replacer, redacted)


def redact_sensitive_data(value: Any) -> Any:
    """Recursively redact every string in a serialized report or MCP response."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {key: redact_sensitive_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    return value


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def redact_model(model: _ModelT) -> _ModelT:
    """Return a validated copy of a Pydantic report with all strings redacted."""
    clean_data = redact_sensitive_data(model.model_dump(mode="python"))
    return type(model).model_validate(clean_data)


def wrap_untrusted_repo_data(content: str) -> str:
    """Fence untrusted repository text so prompt-injection strings are treated strictly as data."""
    sanitized = redact_secrets(content)
    sanitized = sanitized.replace("</untrusted_repo_content>", "&lt;/untrusted_repo_content&gt;")
    sanitized = sanitized.replace("<untrusted_repo_content>", "&lt;untrusted_repo_content&gt;")
    return f"<untrusted_repo_content>\n{sanitized}\n</untrusted_repo_content>"
