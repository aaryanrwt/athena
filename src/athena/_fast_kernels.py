"""Pure, deterministic plain-data kernels eligible for Rust PyO3 acceleration via `fast-anything`."""

from __future__ import annotations

import math
import re
from collections import defaultdict

# Non-backtracking line-anchored structural regexes (never nested quantifiers)
_STRUCTURAL_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "typescript": (
        re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*[<(]"),
        re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)"),
        re.compile(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][A-Za-z0-9_$]*)"),
        re.compile(r"^\s*(?:export\s+)?type\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*="),
        re.compile(r"^\s*(?:export\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\("),
    ),
    "javascript": (
        re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("),
        re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)"),
        re.compile(r"^\s*(?:export\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\("),
        re.compile(r"^\s*(?:module\.)?exports\.([A-Za-z_$][A-Za-z0-9_$]*)\s*="),
    ),
    "go": (
        re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\("),
        re.compile(r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+(?:struct|interface)\b"),
    ),
    "rust": (
        re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
        re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait)\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ),
    "java": (
        re.compile(r"^\s*(?:public|protected|private)?\s*(?:static\s+|final\s+|abstract\s+)*(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ),
    "kotlin": (
        re.compile(r"^\s*(?:public|internal|private|protected)?\s*(?:suspend\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
        re.compile(r"^\s*(?:data\s+|sealed\s+)?(?:class|interface|object)\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ),
    "ruby": (
        re.compile(r"^\s*def\s+(?:self\.)?([A-Za-z_][A-Za-z0-9_]*[!?=]?)"),
        re.compile(r"^\s*(?:class|module)\s+([A-Za-z_][A-Za-z0-9_:]*)"),
    ),
    "php": (
        re.compile(r"^\s*(?:public|protected|private)?\s*(?:static\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
        re.compile(r"^\s*(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ),
    "csharp": (
        re.compile(r"^\s*(?:public|internal|private|protected)?\s*(?:static\s+|sealed\s+|abstract\s+|partial\s+)*(?:class|interface|struct|record|enum)\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ),
    "c": (
        re.compile(r"^\s*(?:typedef\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ),
    "cpp": (
        re.compile(r"^\s*(?:class|struct|namespace)\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ),
    "cuda": (
        re.compile(r"^\s*(?:__global__|__device__|__host__)(?:\s+(?:__device__|__host__|inline|static))*\s+[A-Za-z_][A-Za-z0-9_:<>*&\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
        re.compile(r"^\s*(?:class|struct|namespace)\s+([A-Za-z_][A-Za-z0-9_]*)"),
    ),
    "tex": (
        re.compile(r"^\s*\\(?:sub)*section\*?\{([^}]+)\}"),
        re.compile(r"^\s*\\newcommand\*?\{\\([A-Za-z0-9_]+)\}"),
    ),
}

_IMPORT_PATTERNS: dict[str, re.Pattern[str]] = {
    "typescript": re.compile(r"""^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]"""),
    "javascript": re.compile(r"""^\s*(?:import\s+.*?\s+from\s+|require\s*\(\s*)['"]([^'"]+)['"]"""),
    "go": re.compile(r"""^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?["']([^"']+)["']"""),
    "rust": re.compile(r"""^\s*use\s+([A-Za-z0-9_:]+);"""),
}
_TS_JS_REEXPORT_RE = re.compile(r"""^\s*export\s+(?:\*|\{[^}]+\})\s+from\s+['"]([^'"]+)['"]""")
_PHP_DYNAMIC_RE = re.compile(r"""(?:__callStatic|__call|->\s*(?:bind|singleton)\s*\(|app\s*\(\s*\)\s*->\s*make\s*\()""")

_HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<base_start>\d+)(?:,(?P<base_count>\d+))? \+(?P<target_start>\d+)(?:,(?P<target_count>\d+))? @@(?P<context>.*)$"
)


def compute_community_assignments(
    node_ids: list[str],
    node_is_test: list[bool],
    node_labels: list[str],
    edges: list[tuple[str, str, str, float, str]],
) -> tuple[dict[str, int], dict[str, str]]:
    """Deterministic label-propagation community clustering independent of PYTHONHASHSEED."""
    if not node_ids:
        return {}, {}

    is_test_map = dict(zip(node_ids, node_is_test))
    label_map = dict(zip(node_ids, node_labels))
    sorted_ids = sorted(label_map.keys())
    adj: dict[str, list[tuple[str, float]]] = defaultdict(list)

    for src, tgt, _rel, weight, conf in sorted(edges, key=lambda e: (e[0], e[1], e[2])):
        if src in label_map and tgt in label_map and src != tgt:
            w = weight * (0.5 if conf == "inferred" else 1.0)
            adj[src].append((tgt, w))
            adj[tgt].append((src, w))

    labels: dict[str, int] = {nid: idx for idx, nid in enumerate(sorted_ids)}
    for _ in range(12):
        changed = False
        for nid in sorted_ids:
            neighbors = adj.get(nid)
            if not neighbors:
                continue
            scores: dict[int, float] = defaultdict(float)
            for nb, w in neighbors:
                scores[labels[nb]] += w
            best_comm = min(scores.items(), key=lambda item: (-item[1], item[0]))[0]
            if best_comm != labels[nid]:
                labels[nid] = best_comm
                changed = True
        if not changed:
            break

    groups: dict[int, list[str]] = defaultdict(list)
    for nid in sorted_ids:
        groups[labels[nid]].append(nid)

    ordered_groups = sorted(groups.values(), key=lambda g: (-len(g), g[0]))
    final_comm: dict[str, int] = {}
    community_labels: dict[str, str] = {}
    degree = {nid: len(adj.get(nid, [])) for nid in sorted_ids}

    for cid, members in enumerate(ordered_groups):
        for nid in members:
            final_comm[nid] = cid
        hub = min(
            members,
            key=lambda m: (
                1 if is_test_map[m] else 0,
                -degree[m],
                m,
            ),
        )
        community_labels[str(cid)] = label_map[hub]

    return final_comm, community_labels


def score_graph_trigrams(
    node_ids: list[str],
    labels: list[str],
    file_paths: list[str],
    is_test: list[bool],
    terms: list[str],
    include_tests: bool,
) -> tuple[dict[str, float], list[str]]:
    """Compute trigram + IDF relevance scores and deterministic top seed IDs for graph queries."""
    def _trigrams(text: str) -> set[str]:
        norm = f" {text.lower()} "
        if len(norm) < 3:
            return {norm}
        return {norm[i : i + 3] for i in range(len(norm) - 2)}

    doc_freq: dict[str, int] = defaultdict(int)
    node_trigrams: dict[str, set[str]] = {}
    node_meta: dict[str, tuple[str, str]] = {}
    for nid, label, fpath, test_flag in zip(node_ids, labels, file_paths, is_test):
        if not include_tests and test_flag:
            continue
        label_l = label.lower()
        path_l = fpath.lower()
        node_meta[nid] = (label_l, path_l)
        node_trigrams[nid] = _trigrams(f"{label} {fpath}")
        for term in terms:
            if term in label_l or term in path_l:
                doc_freq[term] += 1

    total_docs = max(1, len(node_trigrams))
    scores: dict[str, float] = {}
    best_by_term: dict[str, tuple[float, str]] = {}

    for nid, tris in node_trigrams.items():
        label_l, path_l = node_meta[nid]
        s = 0.0
        for term in terms:
            idf = math.log(1.0 + total_docs / (1.0 + doc_freq.get(term, 0)))
            t_tris = _trigrams(term)
            overlap = len(tris & t_tris) / max(1, len(t_tris))
            exact_bonus = 2.0 if term in label_l else (1.0 if term in path_l else 0.0)
            term_score = (exact_bonus + overlap) * idf
            s += term_score
            if term_score > 0:
                prev = best_by_term.get(term)
                if prev is None or term_score > prev[0]:
                    best_by_term[term] = (term_score, nid)
        if s > 0:
            scores[nid] = s

    seeds: list[str] = []
    seen_seeds: set[str] = set()
    for _, nid in sorted(best_by_term.values(), key=lambda x: (-x[0], x[1])):
        if nid not in seen_seeds:
            seen_seeds.add(nid)
            seeds.append(nid)
    for nid, _ in sorted(scores.items(), key=lambda x: (-x[1], x[0])):
        if nid not in seen_seeds:
            seen_seeds.add(nid)
            seeds.append(nid)
        if len(seeds) >= 8:
            break

    return scores, seeds


def extract_structural_symbols_raw(
    language: str,
    source: str,
) -> tuple[list[tuple[str, int]], list[str], list[int]]:
    """Extract structural symbols, import targets, and PHP dynamic lines from source text."""
    patterns = _STRUCTURAL_PATTERNS.get(language, ())
    imp_pat = _IMPORT_PATTERNS.get(language)
    symbols: list[tuple[str, int]] = []
    import_targets: list[str] = []
    php_dynamic_lines: list[int] = []

    for idx, line in enumerate(source.splitlines(), start=1):
        if len(line) > 512:
            continue
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("//", "#", "/*", "*", "--")):
            continue
        if imp_pat is not None:
            m_imp = imp_pat.match(line)
            if m_imp:
                import_targets.append(m_imp.group(1))
        if language in ("typescript", "javascript"):
            m_reexp = _TS_JS_REEXPORT_RE.match(line)
            if m_reexp:
                import_targets.append(m_reexp.group(1))
        if language == "php" and _PHP_DYNAMIC_RE.search(line):
            php_dynamic_lines.append(idx)
        for pat in patterns:
            m = pat.match(line)
            if m:
                sym = m.group(1)
                if sym:
                    symbols.append((sym, idx))
                break

    return symbols, import_targets, php_dynamic_lines


def parse_unified_diff_raw(
    diff_text: str,
) -> list[tuple[str, list[tuple[str, int, int, int, int, str]], int, int, bool]]:
    """Parse unified git diff output into plain per-file hunk tuples and line counts."""
    results: list[tuple[str, list[tuple[str, int, int, int, int, str]], int, int, bool]] = []
    if not diff_text.strip():
        return results

    current_file: str | None = None
    hunks: list[tuple[str, int, int, int, int, str]] = []
    current_header: str | None = None
    current_base_start = 0
    current_base_end = 0
    current_target_start = 0
    current_target_end = 0
    current_lines: list[str] = []
    ins_count = 0
    del_count = 0
    is_binary = False

    for line in diff_text.splitlines():
        if line.startswith("diff --git a/"):
            if current_header is not None:
                hunks.append(
                    (
                        current_header,
                        current_base_start,
                        current_base_end,
                        current_target_start,
                        current_target_end,
                        "\n".join(current_lines),
                    )
                )
            current_header = None
            current_base_start = 0
            current_base_end = 0
            current_target_start = 0
            current_target_end = 0
            current_lines = []
            if current_file is not None:
                results.append((current_file, hunks, ins_count, del_count, is_binary))
            current_file = None
            hunks = []
            ins_count = 0
            del_count = 0
            is_binary = False
            parts = line.split(" b/", 1)
            if len(parts) == 2:
                current_file = parts[1].strip()
            continue

        if current_file is None:
            continue

        if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            is_binary = True
            continue

        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            continue

        if (
            line.startswith("--- ")
            or line.startswith("index ")
            or line.startswith("new file ")
            or line.startswith("deleted file ")
        ):
            continue

        hunk_match = _HUNK_HEADER_RE.match(line)
        if hunk_match:
            if current_header is not None:
                hunks.append(
                    (
                        current_header,
                        current_base_start,
                        current_base_end,
                        current_target_start,
                        current_target_end,
                        "\n".join(current_lines),
                    )
                )
            current_lines = []
            current_header = line.strip()
            current_base_start = 0
            current_base_end = 0
            current_target_start = 0
            current_target_end = 0
            b_start = int(hunk_match.group("base_start"))
            b_cnt = int(hunk_match.group("base_count") or "1")
            t_start = int(hunk_match.group("target_start"))
            t_cnt = int(hunk_match.group("target_count") or "1")
            if b_start > 0 and b_cnt > 0:
                current_base_start, current_base_end = b_start, b_start + b_cnt - 1
            elif b_start > 0:
                current_base_start, current_base_end = b_start, b_start
            if t_start > 0 and t_cnt > 0:
                current_target_start, current_target_end = t_start, t_start + t_cnt - 1
            elif t_start > 0:
                current_target_start, current_target_end = t_start, t_start
            continue

        if current_header is not None:
            current_lines.append(line)
            if line.startswith("+") and not line.startswith("+++"):
                ins_count += 1
            elif line.startswith("-") and not line.startswith("---"):
                del_count += 1

    if current_header is not None:
        hunks.append(
            (
                current_header,
                current_base_start,
                current_base_end,
                current_target_start,
                current_target_end,
                "\n".join(current_lines),
            )
        )
    if current_file is not None:
        results.append((current_file, hunks, ins_count, del_count, is_binary))
    return results

# >>> fast-anything: athena._fast_kernels.score_graph_trigrams >>>
# Uses the verified Rust port. FAST_ANYTHING_DISABLE=1 runs the Python above instead.
# Undo with:  fast-anything disable athena._fast_kernels.score_graph_trigrams
def _fast_anything_load():
    import os, sys
    if os.environ.get("FAST_ANYTHING_DISABLE"):
        return None
    lib = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../.fast/lib"))
    if lib not in sys.path:
        sys.path.append(lib)
    try:
        from fa_athena__fast_kernels_score_graph_trigrams import score_graph_trigrams
    except ImportError:
        return None
    return score_graph_trigrams
score_graph_trigrams = _fast_anything_load() or score_graph_trigrams
del _fast_anything_load
# <<< fast-anything: athena._fast_kernels.score_graph_trigrams <<<

# >>> fast-anything: athena._fast_kernels.compute_community_assignments >>>
# Uses the verified Rust port. FAST_ANYTHING_DISABLE=1 runs the Python above instead.
# Undo with:  fast-anything disable athena._fast_kernels.compute_community_assignments
def _fast_anything_load():
    import os, sys
    if os.environ.get("FAST_ANYTHING_DISABLE"):
        return None
    lib = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../.fast/lib"))
    if lib not in sys.path:
        sys.path.append(lib)
    try:
        from fa_athena__fast_kernels_compute_community_assignments import compute_community_assignments
    except ImportError:
        return None
    return compute_community_assignments
compute_community_assignments = _fast_anything_load() or compute_community_assignments
del _fast_anything_load
# <<< fast-anything: athena._fast_kernels.compute_community_assignments <<<

# >>> fast-anything: athena._fast_kernels.extract_structural_symbols_raw >>>
# Uses the verified Rust port. FAST_ANYTHING_DISABLE=1 runs the Python above instead.
# Undo with:  fast-anything disable athena._fast_kernels.extract_structural_symbols_raw
def _fast_anything_load():
    import os, sys
    if os.environ.get("FAST_ANYTHING_DISABLE"):
        return None
    lib = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../.fast/lib"))
    if lib not in sys.path:
        sys.path.append(lib)
    try:
        from fa_athena__fast_kernels_extract_structural_symbols_raw import extract_structural_symbols_raw
    except ImportError:
        return None
    return extract_structural_symbols_raw
extract_structural_symbols_raw = _fast_anything_load() or extract_structural_symbols_raw
del _fast_anything_load
# <<< fast-anything: athena._fast_kernels.extract_structural_symbols_raw <<<
