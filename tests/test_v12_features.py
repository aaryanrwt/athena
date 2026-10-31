"""Offline, deterministic tests for the v1.2.0 features."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from athena import symbol_cache
from athena.ast_analyzer import _parse_multilang_symbols, _parse_python_symbols
from athena.cli import main
from athena.gates import evaluate_semver_gate, required_bump
from athena.html_report import render_html_report
from athena.mcp_config import build_mcp_config
from athena.sarif import breaking_report_to_sarif
from athena.security import AthenaValidationError

pytestmark = pytest.mark.timeout(180)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True, text=True, timeout=60,
    )


def _make_repo(path: Path) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    (path / "lib.py").write_text("def greet(name):\n    return 'hi ' + name\n", encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "init")
    _git(path, "tag", "v1.0.0")
    return path


BREAKING_SRC = "def greet(name, greeting):\n    return greeting + name\n"
ADDITIVE_SRC = "def greet(name):\n    return 'hi ' + name\n\n\ndef farewell(name):\n    return 'bye ' + name\n"


@pytest.fixture(scope="module", autouse=True)
def _no_cache():
    symbol_cache.configure_cache(None)
    yield
    symbol_cache.configure_cache(None)


@pytest.fixture(scope="module")
def breaking_repo(tmp_path_factory) -> Path:
    repo = _make_repo(tmp_path_factory.mktemp("brk") / "repo")
    (repo / "lib.py").write_text(BREAKING_SRC, encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "change greet")
    return repo


@pytest.fixture(scope="module")
def additive_repo(tmp_path_factory) -> Path:
    repo = _make_repo(tmp_path_factory.mktemp("add") / "repo")
    (repo / "lib.py").write_text(ADDITIVE_SRC, encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "add farewell")
    return repo


# ---------------------------------------------------------------- init-mcp

@pytest.mark.parametrize("client", ["claude-desktop", "cursor", "vscode"])
def test_init_mcp_prints_valid_json(client, capsys):
    assert main(["init-mcp", client]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == build_mcp_config(client)
    servers = data.get("mcpServers") or data.get("servers")
    assert servers["athena"]["command"] == "athena"
    assert servers["athena"]["args"] == ["mcp"]


def test_init_mcp_write_requires_path(capsys):
    assert main(["init-mcp", "cursor", "--write"]) == 2
    assert "PATH_REQUIRED" in capsys.readouterr().out


def test_init_mcp_write_never_overwrites_without_force(tmp_path, capsys):
    target = tmp_path / "sub" / "mcp.json"
    assert main(["init-mcp", "vscode", "--write", "--path", str(target)]) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["servers"]["athena"]["type"] == "stdio"
    target.write_text("{}", encoding="utf-8")
    capsys.readouterr()
    assert main(["init-mcp", "vscode", "--write", "--path", str(target)]) == 1
    assert "FILE_EXISTS_OVERWRITE_DENIED" in capsys.readouterr().out
    assert target.read_text(encoding="utf-8") == "{}"
    assert main(["init-mcp", "vscode", "--write", "--path", str(target), "--force"]) == 0
    assert "servers" in json.loads(target.read_text(encoding="utf-8"))


def test_init_mcp_blocks_git_metadata_and_directories(tmp_path, capsys):
    assert main(["init-mcp", "cursor", "--write", "--path", str(tmp_path / ".git" / "mcp.json")]) == 1
    assert "GIT_METADATA_WRITE_BLOCKED" in capsys.readouterr().out
    assert main(["init-mcp", "cursor", "--write", "--path", str(tmp_path)]) == 1


# ------------------------------------------------------------------- SARIF

def test_sarif_structure_from_synthetic_report():
    report = {
        "status": "ok",
        "potential_breaking_changes": [{
            "finding_id": "f1", "title": "Removed foo", "severity": "high", "confidence": "high",
            "file_path": "C:\\evil\\..\\src\\a.py", "change_kind": "removed", "affected_symbol": "foo",
            "evidence_ids": ["ev_001"],
        }],
        "evidence_registry": {"ev_001": {
            "evidence_id": "ev_001", "file_path": "src/a.py",
            "base_line_span": {"start_line": 3, "end_line": 5}, "reason_supports_finding": "gone",
        }},
    }
    sarif = breaking_report_to_sarif(report)
    assert sarif["version"] == "2.1.0" and "$schema" in sarif
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "athena"
    res = run["results"][0]
    assert res["level"] == "error" and res["ruleId"] == "athena/removed"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "evil/src/a.py"
    assert loc["region"] == {"startLine": 3, "endLine": 5}
    assert res["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/a.py"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"athena/removed"}


def test_breaking_changes_cli_sarif(breaking_repo, capsys):
    assert main(["breaking-changes", str(breaking_repo), "--base", "v1.0.0", "--format", "sarif"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    results = sarif["runs"][0]["results"]
    assert results
    for r in results:
        uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/") and ":" not in uri and ".." not in uri.split("/")
    assert any(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "lib.py" for r in results)


# --------------------------------------------------------- check --staged

def test_check_staged_flags_breaking_change(tmp_path, capsys):
    repo = _make_repo(tmp_path / "repo")
    assert main(["check", "--staged", str(repo)]) == 0
    (repo / "lib.py").write_text(BREAKING_SRC, encoding="utf-8")
    assert main(["check", "--staged", str(repo)]) == 0  # unstaged edits are ignored
    _git(repo, "add", "lib.py")
    capsys.readouterr()
    assert main(["check", "--staged", str(repo)]) == 1
    assert "lib.py" in capsys.readouterr().out
    # analysis must not touch the index or refs
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, timeout=30).stdout
    assert status.strip().startswith("M")


def test_check_requires_staged_flag_and_valid_repo(tmp_path, capsys):
    assert main(["check", str(tmp_path)]) == 2
    assert main(["check", "--staged", str(tmp_path / "missing")]) == 2


# ------------------------------------------------------------- report --html

def test_html_report_escapes_everything_and_has_no_external_assets():
    payload = "<script>alert(1)</script>\"'&"
    report = {
        "status": "ok", "base_ref": payload, "target_ref": "HEAD",
        "potential_breaking_changes": [{
            "finding_id": "f1", "title": payload, "severity": payload, "confidence": "high",
            "file_path": payload, "change_kind": payload, "affected_symbol": payload,
            "old_signature": payload, "new_signature": payload, "observed_facts": [payload],
            "affected_callers": [{"caller_file": payload, "line_number": 1, "call_snippet": payload}],
            "evidence_ids": ["e"],
        }],
        "evidence_registry": {"e": {"evidence_id": payload, "file_path": payload,
                                    "reason_supports_finding": payload, "diff_excerpt": payload}},
        "warnings": [payload],
    }
    out = render_html_report(report)
    assert "<script" not in out.lower()
    assert "&lt;script&gt;" in out
    for needle in ("http://", "https://", "src=", "<link", "@import", "url("):
        assert needle not in out


def test_report_html_cli_writes_file_safely(breaking_repo, capsys):
    assert main(["report", str(breaking_repo), "--html", "--base", "v1.0.0", "--output", "out/report.html"]) == 0
    html_file = breaking_repo / "out" / "report.html"
    assert "<!DOCTYPE html>" in html_file.read_text(encoding="utf-8")
    capsys.readouterr()
    assert main(["report", str(breaking_repo), "--html", "--base", "v1.0.0", "--output", "out/report.html"]) == 1
    assert main(["report", str(breaking_repo), "--html", "--base", "v1.0.0", "--output", "../escape.html"]) == 1
    assert not (breaking_repo.parent / "escape.html").exists()
    assert main(["report", str(breaking_repo), "--html", "--base", "v1.0.0"]) == 0
    assert "lib.py" in capsys.readouterr().out
    assert main(["report", str(breaking_repo)]) == 2


# -------------------------------------------------------------- semver-check

def test_required_bump_and_gate_logic():
    assert required_bump(2, 5)[0] == "major"
    assert required_bump(0, 1)[0] == "minor"
    assert required_bump(0, 0)[0] == "patch"
    assert evaluate_semver_gate("major", "minor") and evaluate_semver_gate("minor", "minor")
    assert not evaluate_semver_gate("patch", "minor")
    with pytest.raises(AthenaValidationError):
        evaluate_semver_gate("huge", "patch")


def test_semver_check_cli_breaking(breaking_repo, capsys):
    args = ["semver-check", str(breaking_repo), "--base", "v1.0.0"]
    assert main([*args, "--declared", "patch"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["required_bump"] == "major" and out["gate_passed"] is False
    assert main([*args, "--declared", "minor"]) == 1
    assert main([*args, "--declared", "major"]) == 0


def test_semver_check_cli_additive(additive_repo, capsys):
    args = ["semver-check", str(additive_repo), "--base", "v1.0.0"]
    assert main([*args, "--declared", "patch"]) == 1
    assert json.loads(capsys.readouterr().out)["required_bump"] == "minor"
    assert main([*args, "--declared", "minor"]) == 0


def test_semver_check_rejects_bad_ref(breaking_repo, capsys):
    assert main(["semver-check", str(breaking_repo), "--base=--evil", "--declared", "major"]) == 2


# -------------------------------------------------------------------- cache

PY_SRC = "class A:\n    def m(self, x: int = 1) -> int:\n        raise ValueError\n\n\ndef f(a, *, b=2):\n    return a\n"


def test_cache_roundtrip_matches_uncached_and_hits(tmp_path):
    uncached = _parse_python_symbols(PY_SRC, "m.py")
    cache = symbol_cache.configure_cache(tmp_path / "cache")
    try:
        first = _parse_python_symbols(PY_SRC, "m.py")
        second = _parse_python_symbols(PY_SRC, "m.py")
        assert first == uncached and second == uncached
        assert cache.hits == 1 and cache.misses == 1
        ts = "export function foo(a: number, b: string): void {}\n"
        t1 = _parse_multilang_symbols(ts, "a.ts")
        t2 = _parse_multilang_symbols(ts, "a.ts")
        assert t1 == t2 and cache.hits == 2
        # changed content must miss
        _parse_python_symbols(PY_SRC + "\ndef g():\n    pass\n", "m.py")
        assert cache.misses == 3
    finally:
        symbol_cache.configure_cache(None)
    assert len(list((tmp_path / "cache").glob("*.json"))) == 3


def test_cache_corrupt_and_mismatched_entries_are_misses(tmp_path):
    cache = symbol_cache.SymbolCache(tmp_path)
    key = symbol_cache.compute_cache_key("py", "m.py", PY_SRC)
    for bad in ("{not json", "[]", json.dumps({"schema": 99, "key": key, "data": {}}),
                json.dumps({"schema": 1, "key": "0" * 64, "data": {}}), ""):
        (tmp_path / f"{key}.json").write_text(bad, encoding="utf-8")
        assert cache.get(key) is None
    (tmp_path / f"{key}.json").write_bytes(b"\xff\xfe\x00bad")
    assert cache.get(key) is None
    # a corrupt entry is repaired by the next put
    symbol_cache.configure_cache(tmp_path)
    try:
        assert _parse_python_symbols(PY_SRC, "m.py") == _parse_python_symbols(PY_SRC, "m.py")
    finally:
        symbol_cache.configure_cache(None)


def test_cache_wrong_shape_payload_falls_back_to_parse(tmp_path):
    key = symbol_cache.compute_cache_key("py", "m.py", PY_SRC)
    cache = symbol_cache.SymbolCache(tmp_path)
    assert cache.put(key, {"f": {"unexpected": 1}})
    symbol_cache.configure_cache(tmp_path)
    try:
        assert "f" in _parse_python_symbols(PY_SRC, "m.py")
    finally:
        symbol_cache.configure_cache(None)


def test_cache_rejects_traversal_keys_and_bad_dirs(tmp_path):
    cache = symbol_cache.SymbolCache(tmp_path / "c")
    for evil in ("../../etc/passwd", "..\\x", "a" * 63, "A" * 64, "x/../" + "a" * 60):
        assert cache.get(evil) is None
        assert cache.put(evil, {"a": 1}) is False
    assert not list(tmp_path.glob("*.json"))
    with pytest.raises(AthenaValidationError):
        symbol_cache.SymbolCache(tmp_path / ".git" / "cache")
    with pytest.raises(AthenaValidationError):
        symbol_cache.SymbolCache("bad\x00dir")
    afile = tmp_path / "afile"
    afile.write_text("x", encoding="utf-8")
    with pytest.raises(AthenaValidationError):
        symbol_cache.SymbolCache(afile)


def test_cli_cache_dir_flag_and_env(breaking_repo, tmp_path, monkeypatch, capsys):
    cache_dir = tmp_path / "cli-cache"
    assert main(["--cache-dir", str(cache_dir), "breaking-changes", str(breaking_repo), "--base", "v1.0.0"]) == 0
    assert list(cache_dir.glob("*.json"))
    capsys.readouterr()
    assert main(["--cache-dir", str(tmp_path / ".git" / "c"), "inspect", str(breaking_repo)]) == 2
    monkeypatch.setenv("ATHENA_CACHE_DIR", str(tmp_path / "env-cache"))
    assert main(["breaking-changes", str(breaking_repo), "--base", "v1.0.0"]) == 0
    assert list((tmp_path / "env-cache").glob("*.json"))
    monkeypatch.delenv("ATHENA_CACHE_DIR")
    main(["inspect", str(breaking_repo)])
    assert symbol_cache.get_active_cache() is None


def test_symbol_signature_change_accepts_behavior_changed():
    from athena.models import SymbolSignatureChange
    change = SymbolSignatureChange(
        file_path="pkg/recurse.py",
        symbol_name="compute_tree",
        symbol_kind="function",
        change_kind="behavior_changed",
        details="Unconditional infinite recursion detected in recursive function",
        is_breaking_candidate=True,
        severity="high",
    )
    assert change.change_kind == "behavior_changed"
    assert change.severity == "high"


def test_cli_ui_subcommand(monkeypatch, capsys):
    from athena.tui import run_interactive_ui
    # Feed 'q' to exit immediately
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")
    code = run_interactive_ui(".")
    assert code == 0
    captured = capsys.readouterr()
    assert "Welcome to Athena Studio" in captured.out
    assert "Athena checks the callers" in captured.out
