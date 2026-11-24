"""Zero-Vector-DB Graph Query Engine: Trigram + IDF Scoring & Hub-Guarded BFS.

Token-budgeted subgraph traversal, non-test god-node filtering, community
inspection, and shortest-path queries.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict, deque
from typing import Any

from athena._fast_kernels import score_graph_trigrams
from athena.graph_store import CodeGraph, GraphEdge

_CHARS_PER_TOKEN = 4
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _build_adj(graph: CodeGraph) -> tuple[dict[str, list[tuple[str, GraphEdge]]], dict[str, int]]:
    adj: dict[str, list[tuple[str, GraphEdge]]] = defaultdict(list)
    degree: dict[str, int] = defaultdict(int)
    for edge in graph.edges:
        adj[edge.source].append((edge.target, edge))
        adj[edge.target].append((edge.source, edge))
        degree[edge.source] += 1
        degree[edge.target] += 1
    return adj, degree


def _p99_hub_threshold(degree: dict[str, int]) -> int:
    if not degree:
        return 50
    vals = sorted(degree.values())
    idx = min(len(vals) - 1, int(len(vals) * 0.99))
    return max(50, vals[idx])


def query_code_graph(
    graph: CodeGraph,
    query: str,
    *,
    depth: int = 2,
    token_budget: int = 2000,
    include_tests: bool = False,
) -> dict[str, Any]:
    """Query the code graph using character-trigram + IDF scoring and hub-guarded BFS."""
    terms = [t.lower() for t in _TOKEN_RE.findall(query) if len(t) >= 2]
    if not terms:
        return {
            "status": "ok",
            "query": query,
            "matches": [],
            "subgraph_nodes": [],
            "subgraph_edges": [],
            "estimated_tokens": 0,
            "completeness": graph.completeness,
        }

    node_map = {n.id: n for n in graph.nodes}
    adj, degree = _build_adj(graph)
    hub_cap = _p99_hub_threshold(degree)

    # Single-pass trigram + IDF scoring
    scores, seeds = score_graph_trigrams(
        [n.id for n in graph.nodes],
        [n.label for n in graph.nodes],
        [n.file_path for n in graph.nodes],
        [n.is_test_or_utility for n in graph.nodes],
        terms,
        include_tests,
    )
    seen_seeds: set[str] = set(seeds)

    # Hub-guarded BFS
    visited: set[str] = set(seeds)
    queue: deque[tuple[str, int]] = deque((s, 0) for s in seeds)
    collected_edges: list[GraphEdge] = []
    seen_edge_keys: set[tuple[str, str, str]] = set()

    while queue:
        curr, d = queue.popleft()
        if d >= max(1, min(depth, 4)):
            continue
        # Do not transit-expand through super-hubs
        if curr not in seen_seeds and degree.get(curr, 0) >= hub_cap:
            continue
        for nb, edge in adj.get(curr, []):
            nb_node = node_map.get(nb)
            if nb_node is None or (not include_tests and nb_node.is_test_or_utility):
                continue
            ek = (edge.source, edge.target, edge.relation)
            if ek not in seen_edge_keys:
                seen_edge_keys.add(ek)
                collected_edges.append(edge)
            if nb not in visited:
                visited.add(nb)
                queue.append((nb, d + 1))

    # Budget-pack nodes & edges
    char_budget = max(256, token_budget * _CHARS_PER_TOKEN)
    used_chars = 0
    out_nodes: list[dict[str, Any]] = []
    included_ids: set[str] = set()

    ordered_nodes = sorted(
        visited,
        key=lambda nid: (-scores.get(nid, 0.0), nid),
    )
    for nid in ordered_nodes:
        n = node_map[nid]
        item = n.model_dump(mode="json")
        cost = len(str(item))
        if used_chars + cost > char_budget and out_nodes:
            break
        used_chars += cost
        included_ids.add(nid)
        out_nodes.append(item)

    out_edges = [
        e.model_dump(mode="json")
        for e in collected_edges
        if e.source in included_ids and e.target in included_ids
    ][:100]

    return {
        "status": "ok",
        "query": query,
        "graph_evidence_id": graph.graph_evidence_id,
        "completeness": graph.completeness,
        "seed_count": len(seeds),
        "subgraph_nodes": out_nodes,
        "subgraph_edges": out_edges,
        "estimated_tokens": max(1, used_chars // _CHARS_PER_TOKEN) if out_nodes else 0,
    }


def get_god_nodes(
    graph: CodeGraph,
    *,
    limit: int = 10,
    include_tests: bool = False,
) -> list[dict[str, Any]]:
    """Return highest-degree architectural hub nodes, excluding tests/utilities by default."""
    _, degree = _build_adj(graph)
    candidates = [
        n
        for n in graph.nodes
        if (include_tests or not n.is_test_or_utility) and n.kind != "module"
    ]
    if not candidates:
        candidates = [n for n in graph.nodes if include_tests or not n.is_test_or_utility]
    ranked = sorted(candidates, key=lambda n: (-degree.get(n.id, 0), n.id))
    return [
        {
            "id": n.id,
            "label": n.label,
            "kind": n.kind,
            "file_path": n.file_path,
            "line": n.line,
            "degree": degree.get(n.id, 0),
            "community": n.community,
            "evidence_id": n.evidence_id,
        }
        for n in ranked[: max(1, limit)]
    ]


def shortest_path_between(
    graph: CodeGraph,
    source_query: str,
    target_query: str,
) -> dict[str, Any]:
    """Find the shortest path between two symbols (matching exact ID first, then label)."""
    node_map = {n.id: n for n in graph.nodes}

    def _resolve(q: str) -> str | None:
        if q in node_map:
            return q
        ql = q.lower()
        exact = [n.id for n in graph.nodes if n.label.lower() == ql]
        if exact:
            return sorted(exact)[0]
        partial = [n.id for n in graph.nodes if ql in n.label.lower() or ql in n.id.lower()]
        return sorted(partial)[0] if partial else None

    src_id = _resolve(source_query)
    tgt_id = _resolve(target_query)
    if src_id is None or tgt_id is None:
        return {
            "status": "not_found",
            "source_resolved": src_id,
            "target_resolved": tgt_id,
            "path": [],
        }

    adj, _ = _build_adj(graph)
    queue: deque[list[str]] = deque([[src_id]])
    visited = {src_id}
    while queue:
        path = queue.popleft()
        curr = path[-1]
        if curr == tgt_id:
            return {
                "status": "ok",
                "hops": len(path) - 1,
                "path": [
                    {
                        "id": nid,
                        "label": node_map[nid].label,
                        "file_path": node_map[nid].file_path,
                        "line": node_map[nid].line,
                    }
                    for nid in path
                ],
            }
        for nb, _ in sorted(adj.get(curr, []), key=lambda x: x[0]):
            if nb not in visited:
                visited.add(nb)
                queue.append([*path, nb])

    return {"status": "disconnected", "source_resolved": src_id, "target_resolved": tgt_id, "path": []}


def get_graph_stats(graph: CodeGraph) -> dict[str, Any]:
    """Return high-level statistics and residual unknown counts for a CodeGraph."""
    return {
        "status": "ok",
        "schema_version": graph.schema_version,
        "graph_evidence_id": graph.graph_evidence_id,
        "completeness": graph.completeness,
        "total_files_scanned": graph.total_files_scanned,
        "skipped_files": graph.skipped_files,
        "parse_errors": graph.parse_errors,
        "total_nodes": len(graph.nodes),
        "total_edges": len(graph.edges),
        "total_communities": len(graph.community_labels),
        "total_unknowns": len(graph.unknowns),
        "god_nodes": get_god_nodes(graph, limit=5),
    }


def get_neighbors(
    graph: CodeGraph,
    node_query: str,
    *,
    limit: int = 25,
) -> dict[str, Any]:
    """Return direct neighbors of a node, matching exact node ID before label."""
    node_map = {n.id: n for n in graph.nodes}
    target_id: str | None = None
    if node_query in node_map:
        target_id = node_query
    else:
        ql = node_query.lower()
        exact = [n.id for n in graph.nodes if n.label.lower() == ql]
        target_id = min(exact) if exact else None
    if target_id is None:
        return {"status": "not_found", "node_query": node_query, "neighbors": []}

    adj, _ = _build_adj(graph)
    seen: set[str] = set()
    neighbors: list[dict[str, Any]] = []
    for nb_id, edge in sorted(adj.get(target_id, []), key=lambda x: x[0]):
        if nb_id in seen or nb_id not in node_map:
            continue
        seen.add(nb_id)
        nb = node_map[nb_id]
        neighbors.append(
            {
                "id": nb.id,
                "label": nb.label,
                "kind": nb.kind,
                "file_path": nb.file_path,
                "relation": edge.relation,
                "confidence": edge.confidence,
            }
        )
        if len(neighbors) >= max(1, limit):
            break
    return {"status": "ok", "node_id": target_id, "neighbors": neighbors}


def get_community(graph: CodeGraph, community_id: int) -> dict[str, Any]:
    """Return all nodes belonging to a deterministic community cluster."""
    members = [
        {
            "id": n.id,
            "label": n.label,
            "kind": n.kind,
            "file_path": n.file_path,
            "line": n.line,
        }
        for n in graph.nodes
        if n.community == community_id
    ]
    return {
        "status": "ok" if members else "not_found",
        "community_id": community_id,
        "label": graph.community_labels.get(str(community_id), ""),
        "members": members,
    }
