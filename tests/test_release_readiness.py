"""Release-readiness, cross-repo issue regression, and architecture guard tests for v1.3.0."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from athena import __version__
from athena.agent_installer import _HERMES_PLUGIN_YAML
from athena.debt_tracker import scan_shortcut_debt
from athena.evidence_store import resolve_completeness
from athena.graph_query import get_community, get_neighbors
from athena.graph_store import build_code_graph
from athena.mcp_server import _TOOL_CATALOG_METADATA, mcp_app

_REPO_ROOT = Path(__file__).resolve().parents[1]


def test_version_and_docs_sync() -> None:
    assert __version__ == "1.3.2"
    assert 'version: "1.3.2"' in _HERMES_PLUGIN_YAML
    changelog = (_REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 1.3.2" in changelog
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "v1.3.2" in readme
    skill = (_REPO_ROOT / "skills" / "athena" / "SKILL.md").read_text(encoding="utf-8")
    assert "query_code_graph" in skill and "shortcut:" in skill

    # Every relative file link/img in README.md must exist on disk
    for rel in re.findall(r'(?:src="|\]\()([^)"#]+)', readme):
        if rel.startswith(("http://", "https://", "mailto:", "#")):
            continue
        assert (_REPO_ROOT / rel).exists(), f"Broken README link: {rel}"


def test_mcp_catalog_parity_and_annotations() -> None:
    async def _check() -> None:
        tools = await mcp_app.list_tools()
        registered = {t.name for t in tools}
        cataloged = {t["name"] for t in _TOOL_CATALOG_METADATA}
        assert registered == cataloged
        for t in tools:
            assert t.annotations is not None

    asyncio.run(_check())


def test_completeness_never_defaults_to_complete_on_gaps() -> None:
    assert resolve_completeness(skipped_files=1) == "partial"
    assert resolve_completeness(unresolved_unknowns=1) == "partial"
    assert resolve_completeness(truncated=True) == "partial"
    assert resolve_completeness(parse_errors=1) == "partial"
    assert resolve_completeness() == "complete"


def test_utf8_bom_comment_fabrication_and_collision_regressions(tmp_path: Path) -> None:
    repo = tmp_path / "reg_repo"
    repo.mkdir()
    # UTF-8 BOM + Python def + shortcut marker binding
    (repo / "bom_mod.py").write_bytes(
        "\ufeffdef first_fn():\n    # shortcut: linear scan, upgrade at 10k rows\n    return 1\n".encode("utf-8")
    )
    # TS file with comment-only fake function + two functions sharing a name in the same file
    (repo / "edge.ts").write_text(
        "// export function fakeFromComment() {}\n"
        "/* function alsoFake() {} */\n"
        "export function realFn() { return 1; }\n"
        "export function realFn() { return 2; }\n",
        encoding="utf-8",
    )

    cg = build_code_graph(repo, persist=False, use_cache=False)
    labels = [n.label for n in cg.nodes]
    assert "first_fn" in labels
    assert "fakeFromComment" not in labels
    assert "alsoFake" not in labels
    assert labels.count("realFn") == 2
    assert len({n.id for n in cg.nodes}) == len(cg.nodes)

    debt = scan_shortcut_debt(repo)
    assert debt.total_shortcuts == 1
    assert debt.items[0].enclosing_symbol == "first_fn"

    # Exact ID resolution in get_neighbors & get_community
    nb = get_neighbors(cg, "mod:bom_mod.py")
    assert nb["status"] == "ok" and any(x["label"] == "first_fn" for x in nb["neighbors"])
    comm = get_community(cg, 0)
    assert comm["status"] == "ok" and len(comm["members"]) >= 1


def test_metaclass_and_runtime_patching_flagged_as_unknowns(tmp_path: Path) -> None:
    repo = tmp_path / "meta_repo"
    repo.mkdir()
    (repo / "meta.py").write_text(
        "class Meta(type):\n"
        "    pass\n\n"
        "class Plugin(metaclass=Meta):\n"
        "    def __init_subclass__(cls, **kwargs):\n"
        "        setattr(cls, 'injected', True)\n",
        encoding="utf-8",
    )
    cg = build_code_graph(repo, persist=False, use_cache=False)
    assert cg.completeness == "partial"
    details = " ".join(u.detail for u in cg.unknowns)
    assert "metaclass" in details
    assert "__init_subclass__" in details
    assert "setattr" in details
