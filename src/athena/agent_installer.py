"""Transactional Cross-Agent Plugin, Hook & Skill Installer (`athena install`).

Provides SHA-256 backup and readback verification across Hermes, OpenClaw,
Claude Code, Codex, Cursor, and Pi, using session-scoped state and direct
script invocation.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal

AgentTarget = Literal["hermes", "openclaw", "claude-code", "codex", "cursor", "pi"]
SUPPORTED_AGENTS: tuple[AgentTarget, ...] = (
    "hermes",
    "openclaw",
    "claude-code",
    "codex",
    "cursor",
    "pi",
)

_CORE_SKILL_MD = """---
name: athena
description: Local-first evidence-backed code knowledge graph, breaking-change AST analyzer, and minimal-diff discipline.
---

# Athena Agent Protocol

1. Query `get_repo_map` or `query_code_graph` before broad grep/read loops.
2. Check breaking changes & callers (`detect_potential_breaking_changes` / `athena check --staged`) before finalizing edits.
3. Reuse existing helpers; never cut security, validation, or error handling; add a test for non-trivial logic.
4. Mark deliberate deferrals with `# shortcut: <limit>, <when to upgrade>`.
5. Prefer `detail="summary"` and page via `inspect_analysis_view`.
"""

_HERMES_PLUGIN_YAML = """name: athena
version: "1.3.3"
description: "Athena local-first code graph, repo map, and breaking-change guard for Hermes."
entry: "__init__.py"
hooks:
  - pre_llm_call
"""

_HERMES_INIT_PY = '''"""Athena Hermes Agent Plugin (cache-stable pre_llm_call injection)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _get_repo_map_cached(project_dir: str) -> str:
    try:
        proc = subprocess.run(
            ["athena", "map", project_dir, "--max-chars", "1800"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=3,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def register(ctx) -> None:
    """Register cache-stable Athena context hook with Hermes."""
    injected_sessions: set[str] = set()

    def pre_llm_call(event: dict) -> dict | None:
        session_id = str(event.get("session_id") or os.getpid())
        if session_id in injected_sessions:
            return None
        injected_sessions.add(session_id)
        cwd = str(event.get("cwd") or Path.cwd())
        repo_map = _get_repo_map_cached(cwd)
        if not repo_map:
            return None
        return {"system_appendix": f"\\n[Athena Codebase Map]\\n{repo_map}\\n"}

    ctx.hook("pre_llm_call", pre_llm_call)
'''

_CLAUDE_CODEX_HOOK_PY = '''"""Athena SessionStart & PreToolUse Hook (session-scoped, UTF-8 safe, no inline node -e)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    raw = sys.stdin.buffer.read().decode("utf-8", errors="replace") if not sys.stdin.isatty() else "{}"
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}

    session_id = str(payload.get("session_id") or os.environ.get("ATHENA_SESSION_ID") or "default").replace(chr(0), "")
    safe_sid = "".join(c if c.isalnum() or c in "-_" else "_" for c in session_id)[:64] or "default"
    state_dir = Path(os.environ.get("TMPDIR") or os.environ.get("TEMP") or "/tmp") / "athena_sessions"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / f"{safe_sid}.json"

    event_name = str(payload.get("hook_event_name") or (sys.argv[1] if len(sys.argv) > 1 else "SessionStart")).replace(chr(0), "")
    raw_cwd = str(payload.get("cwd") or Path.cwd()).replace(chr(0), "").strip()
    if raw_cwd.startswith("-"):
        return 0
    try:
        cwd = str(Path(raw_cwd).resolve())
    except OSError:
        return 0

    if event_name == "SessionStart":
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "athena", "map", cwd, "--max-chars", "1800"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=3,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": proc.stdout.strip()}}))
        except Exception:
            pass
        return 0

    if event_name == "PreToolUse":
        # Strictly advisory guidance; never overrides user permission or deny rules.
        tool_name = str(payload.get("tool_name") or "").replace(chr(0), "")
        if tool_name in {"Grep", "Glob", "Read"} and not state_file.exists():
            state_file.write_text(json.dumps({"nudged": True}), encoding="utf-8")
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": "Athena tip: prefer `query_code_graph` or `get_repo_map` before broad file/grep scans.",
                }
            }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

_CURSOR_RULE_MDC = """---
description: Athena local-first code graph, repo map, and breaking-change guard
alwaysApply: true
---

# Athena Agent Protocol
- Query `get_repo_map` or `query_code_graph` before broad grep/read loops.
- Run `detect_potential_breaking_changes` / `athena check --staged` before finalizing API changes.
- Reuse existing helpers; mark deliberate deferrals with `# shortcut: <limit>, <when to upgrade>`.
"""

_PI_EXTENSION_JS = """// Athena Pi Extension (prompt-cache-stable section injection)
export default function activate(pi) {
  pi.on("before_agent_start", async (event) => {
    if (event.systemPromptOptions?.sections) {
      event.systemPromptOptions.sections.athena =
        "Athena: query get_repo_map/query_code_graph first; verify breaking changes before commit; mark deferrals with shortcut:.";
    }
  });
}
"""


def _planned_files_for_agent(target_dir: Path, agent: AgentTarget) -> dict[Path, str]:
    if agent == "hermes":
        base = target_dir / ".hermes" / "plugins" / "athena"
        return {
            base / "plugin.yaml": _HERMES_PLUGIN_YAML,
            base / "__init__.py": _HERMES_INIT_PY,
            base / "SKILL.md": _CORE_SKILL_MD,
        }
    if agent == "openclaw":
        base = target_dir / ".openclaw" / "skills" / "athena"
        return {
            base / "SKILL.md": _CORE_SKILL_MD,
        }
    if agent in {"claude-code", "codex"}:
        folder = ".claude" if agent == "claude-code" else ".codex"
        hook_script = target_dir / folder / "hooks" / "athena_hook.py"
        hooks_cfg = {
            "hooks": {
                "SessionStart": [{"hooks": [{"type": "command", "command": f"python \"{hook_script.as_posix()}\" SessionStart"}]}],
                "PreToolUse": [{"matcher": "Grep|Glob|Read", "hooks": [{"type": "command", "command": f"python \"{hook_script.as_posix()}\" PreToolUse"}]}],
            }
        }
        return {
            target_dir / folder / "skills" / "athena" / "SKILL.md": _CORE_SKILL_MD,
            hook_script: _CLAUDE_CODEX_HOOK_PY,
            target_dir / folder / "athena-hooks.json": json.dumps(hooks_cfg, indent=2),
        }
    if agent == "cursor":
        return {
            target_dir / ".cursor" / "rules" / "athena.mdc": _CURSOR_RULE_MDC,
        }
    if agent == "pi":
        return {
            target_dir / ".pi" / "extensions" / "athena.js": _PI_EXTENSION_JS,
            target_dir / ".pi" / "skills" / "athena" / "SKILL.md": _CORE_SKILL_MD,
        }
    raise ValueError(f"Unsupported agent target: {agent}")


def install_agent_integration(
    target_dir: str | Path,
    agent: AgentTarget,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Transactionally install Athena skills/hooks for an AI coding agent with SHA-256 backups."""
    if agent not in SUPPORTED_AGENTS:
        return {
            "status": "error",
            "error_code": "UNSUPPORTED_AGENT",
            "error_message": f"Unsupported agent '{agent}'. Expected one of: {', '.join(SUPPORTED_AGENTS)}.",
        }

    root = Path(target_dir).resolve()
    if not root.exists() or not root.is_dir():
        return {
            "status": "error",
            "error_code": "INVALID_TARGET_DIR",
            "error_message": f"Target directory does not exist: {target_dir}",
        }

    planned = _planned_files_for_agent(root, agent)
    plan_records: list[dict[str, Any]] = []

    for dest, content in planned.items():
        if dest.is_symlink():
            return {
                "status": "error",
                "error_code": "SYMLINK_BLOCKED",
                "error_message": f"Refusing to write through symlink: {dest}",
            }
        action = "update" if dest.exists() else "create"
        plan_records.append(
            {
                "path": str(dest),
                "action": action,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()[:16],
            }
        )

    if dry_run:
        return {
            "status": "ok",
            "dry_run": True,
            "agent": agent,
            "target_dir": str(root),
            "plan": plan_records,
        }

    backups: list[str] = []
    written: list[str] = []
    for dest, content in planned.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            old_bytes = dest.read_bytes()
            old_sha = hashlib.sha256(old_bytes).hexdigest()[:12]
            backup_path = dest.with_name(f"{dest.name}.athena.backup.{old_sha}")
            backup_path.write_bytes(old_bytes)
            backups.append(str(backup_path))

        tmp_path = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
        tmp_path.write_text(content, encoding="utf-8")
        os.replace(tmp_path, dest)

        # Readback verification before reporting installation success
        if dest.read_text(encoding="utf-8") != content:
            return {
                "status": "error",
                "error_code": "READBACK_VERIFICATION_FAILED",
                "error_message": f"Readback mismatch after writing {dest}",
            }
        written.append(str(dest))

    return {
        "status": "ok",
        "dry_run": False,
        "agent": agent,
        "target_dir": str(root),
        "written": written,
        "backups": backups,
    }
