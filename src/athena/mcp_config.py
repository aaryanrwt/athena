"""Ready-made MCP client configuration snippets for ``athena init-mcp``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from athena.security import AthenaValidationError, WINDOWS_RESERVED_NAMES, write_text_safely

CLIENTS = ("claude-desktop", "cursor", "vscode")

_SERVER_COMMAND = "athena"
_SERVER_ARGS = ["mcp"]


def build_mcp_config(client: str) -> dict[str, Any]:
    """Return the JSON-serializable MCP configuration for a supported client."""
    if client in ("claude-desktop", "cursor"):
        return {"mcpServers": {"athena": {"command": _SERVER_COMMAND, "args": list(_SERVER_ARGS)}}}
    if client == "vscode":
        return {
            "servers": {
                "athena": {"type": "stdio", "command": _SERVER_COMMAND, "args": list(_SERVER_ARGS)},
            }
        }
    raise AthenaValidationError("UNKNOWN_MCP_CLIENT", f"Unsupported client '{client}'. Choose one of: {', '.join(CLIENTS)}.")


def render_mcp_config(client: str) -> str:
    return json.dumps(build_mcp_config(client), indent=2) + "\n"


def write_mcp_config(client: str, target: str | Path, force: bool = False) -> Path:
    """Write the config to an explicit file path; never overwrites unless ``force`` is set."""
    raw = str(target).strip()
    if not raw or "\x00" in raw:
        raise AthenaValidationError("INVALID_OUTPUT_PATH", "Target path is invalid.")
    path = Path(raw).expanduser()
    for part in path.parts:
        if part.lower() == ".git":
            raise AthenaValidationError("GIT_METADATA_WRITE_BLOCKED", f"Refusing to write inside Git metadata: {raw}")
        if Path(part).stem.upper() in WINDOWS_RESERVED_NAMES:
            raise AthenaValidationError("RESERVED_DEVICE_NAME_BLOCKED", f"Reserved device name in path: {raw}")
    resolved = path.resolve(strict=False)
    if resolved.is_dir():
        raise AthenaValidationError("INVALID_OUTPUT_PATH", f"Target is a directory, expected a file path: {resolved}")
    if resolved.exists() and not force:
        raise AthenaValidationError(
            "FILE_EXISTS_OVERWRITE_DENIED",
            f"Target file '{resolved}' already exists. Pass --force to overwrite it.",
        )
    write_text_safely(resolved, render_mcp_config(client), overwrite=force)
    return resolved
