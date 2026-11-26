"""Deterministic, Read-Only Git Repository Inspector & Diff Extractor."""

from __future__ import annotations

import os
import re
# Git is invoked with a fixed executable, shell=False, and validated revisions.
import subprocess  # nosec B404
from dataclasses import dataclass, field
from pathlib import Path

from athena._fast_kernels import _HUNK_HEADER_RE, parse_unified_diff_raw
from athena.models import (
    ChangedFileDelta,
    CommitSummaryItem,
    EvidenceRecord,
    LineSpan,
    RepositoryStatusReport,
)
from athena.security import (
    AthenaValidationError,
    is_safe_repo_file,
    redact_secrets,
    validate_git_revision,
    validate_repo_path,
)

LOCKFILE_AND_GENERATED_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "cargo.lock",
    "gemfile.lock",
    "composer.lock",
    "go.sum",
}

IGNORED_DIR_PREFIXES = (
    "node_modules/",
    "vendor/",
    "dependencies/",
    "third_party/",
    "3rdparty/",
    "external/",
    "singleheader/",
    "deprecated/",
    ".yarn/",
    "dist/",
    "build/",
    ".venv/",
    "venv/",
    "__pycache__/",
)

MAX_BOUNDED_DIFF_CHARS = 3500
MAX_EVIDENCE_EXCERPT_CHARS = 700
MAX_SOURCE_BLOB_BYTES = 512 * 1024  # 512 KB cap for AST source inspection

_CONVENTIONAL_HEADER_RE = re.compile(
    r"^(?P<type>[a-zA-Z]+)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?:\s*(?P<subject>.+)$"
)


@dataclass
class ParsedHunk:
    header: str
    base_span: LineSpan | None
    target_span: LineSpan | None
    excerpt: str


@dataclass
class RawRangeExtraction:
    repo_path: Path
    base_ref: str
    target_ref: str
    resolved_base_sha: str
    resolved_target_sha: str
    commits: list[CommitSummaryItem] = field(default_factory=list)
    changed_files: list[ChangedFileDelta] = field(default_factory=list)
    base_blobs: dict[str, str] = field(default_factory=dict)
    target_blobs: dict[str, str] = field(default_factory=dict)
    evidence_registry: dict[str, EvidenceRecord] = field(default_factory=dict)
    working_tree_stats: dict[str, tuple[int, int]] = field(default_factory=dict)


def detect_working_tree_drift(extraction: RawRangeExtraction) -> list[str]:
    """Stat-first TOCTOU check: return any WORKING_TREE files modified mid-analysis."""
    if extraction.resolved_target_sha != "WORKING_TREE" or not extraction.working_tree_stats:
        return []
    drifted: list[str] = []
    for rel_path, (orig_mtime_ns, orig_size) in sorted(extraction.working_tree_stats.items()):
        candidate = extraction.repo_path / rel_path
        try:
            st = candidate.stat()
        except OSError:
            drifted.append(rel_path)
            continue
        if st.st_mtime_ns != orig_mtime_ns or st.st_size != orig_size:
            drifted.append(rel_path)
    return drifted


def _build_git_env() -> dict[str, str]:
    git_env = os.environ.copy()
    git_env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            # Static analysis must never turn a blobless clone into an implicit
            # network operation. Missing promised objects are reported instead.
            "GIT_NO_LAZY_FETCH": "1",
        }
    )
    return git_env


def run_git_command(
    repo_path: Path,
    args: list[str],
    timeout: int = 30,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a read-only Git command with argument list (shell=False) and UTF-8 decoding."""
    cmd = [
        "git",
        "-c",
        "core.quotePath=false",
        "-c",
        "diff.noprefix=false",
        "-c",
        "diff.mnemonicPrefix=false",
        "-c",
        "color.ui=never",
        *args,
    ]
    git_env = _build_git_env()
    try:
        # User-controlled revisions are validated before reaching this shell-free call.
        proc = subprocess.run(  # nosec B603
            cmd,
            cwd=str(repo_path),
            input=input_text,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=git_env,
        )
    except subprocess.TimeoutExpired:
        if check:
            raise AthenaValidationError(
                "GIT_COMMAND_TIMEOUT",
                f"Git command timed out after {timeout}s ({' '.join(args[:3])}).",
            )
        return subprocess.CompletedProcess(cmd, returncode=124, stdout="", stderr=f"Timed out after {timeout}s")
    except OSError as exc:
        if check:
            raise AthenaValidationError(
                "GIT_COMMAND_FAILED",
                f"Git command failed ({' '.join(args[:3])}): {exc}",
            )
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr=str(exc))

    if check and proc.returncode != 0:
        stderr_clean = redact_secrets((proc.stderr or proc.stdout or "").strip())
        raise AthenaValidationError(
            "GIT_COMMAND_FAILED",
            f"Git command failed ({' '.join(args[:3])}): {stderr_clean}",
        )
    return proc


def decode_bytes_safely(raw: bytes) -> str:
    """Decode arbitrary repository bytes gracefully across UTF-8, BOM, cp1252, and latin-1."""
    if not raw:
        return ""
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc).replace("\r\n", "\n")
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").replace("\r\n", "\n")


def _is_lockfile_or_generated(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").lower().lstrip("./")
    basename = norm.rsplit("/", 1)[-1]
    if basename in LOCKFILE_AND_GENERATED_NAMES:
        return True
    if norm.endswith((".min.js", ".min.css", ".map", ".lock", ".pb.go", "_pb2.py")):
        return True
    wrapped = f"/{norm}"
    return any(norm.startswith(prefix) or f"/{prefix}" in wrapped for prefix in IGNORED_DIR_PREFIXES)


_NON_API_TOOLING_BASENAMES = frozenset(
    {
        "noxfile.py",
        "fabfile.py",
        "setup.py",
        "conftest.py",
        "tasks.py",
        "manage.py",
        "gulpfile.js",
        "gruntfile.js",
    }
)
_NON_API_TOOLING_DIRS = frozenset(
    {
        "scripts",
        "script",
        "benchmarks",
        "benchmark",
        "bench",
        "examples",
        "example",
        "samples",
        "sample",
        "tools",
        "devtools",
        "hack",
        "ci",
        ".github",
    }
)


def is_non_api_tooling_file(rel_path: str) -> bool:
    """Return True for build/dev/example/benchmark scripts that are not public library APIs."""
    norm = rel_path.replace("\\", "/").lower().lstrip("./")
    if not norm:
        return False
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return False
    basename = parts[-1]
    if basename in _NON_API_TOOLING_BASENAMES:
        return True
    if basename.endswith((".config.js", ".config.ts", ".config.mjs", ".config.cjs")):
        return True
    return any(seg in _NON_API_TOOLING_DIRS for seg in parts[:-1])


def _is_test_file(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").lower()
    basename = norm.rsplit("/", 1)[-1]
    return (
        "/test/" in f"/{norm}"
        or "/tests/" in f"/{norm}"
        or "/testing/" in f"/{norm}"
        or "/__tests__/" in f"/{norm}"
        or "/spec/" in f"/{norm}"
        or "/specs/" in f"/{norm}"
        or "/features/" in f"/{norm}"
        or basename.startswith("test_")
        or basename.endswith((
            "_test.py",
            ".test.ts",
            ".spec.ts",
            ".test.tsx",
            ".spec.tsx",
            ".test.js",
            ".spec.js",
            ".test.jsx",
            ".spec.jsx",
            "_test.go",
            "_test.cpp",
            "_test.cc",
            "_test.c",
            "_test.rs",
            "_spec.rb",
            "test.java",
            "tests.java",
            "test.cs",
            "tests.cs",
            "test.php",
            "tests.php",
            "tests.swift",
            "test.swift",
            "spec.scala",
            "test.scala",
            "test.kt",
            "tests.kt",
        ))
    )


def _is_doc_file(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").lower()
    return (
        norm.endswith((".md", ".markdown", ".rst", ".adoc"))
        or norm.startswith(("docs/", "doc/", "changelog/", ".changeset/"))
        or "/docs/" in f"/{norm}"
        or "/doc/" in f"/{norm}"
    )


def _parse_conventional_commit(subject: str, body: str) -> tuple[str | None, str | None, bool]:
    match = _CONVENTIONAL_HEADER_RE.match(subject.strip())
    conv_type: str | None = None
    conv_scope: str | None = None
    breaking = False
    if match:
        conv_type = match.group("type").lower()
        conv_scope = match.group("scope")
        if match.group("breaking") == "!":
            breaking = True
    full_text = f"{subject}\n{body}"
    if "BREAKING CHANGE:" in full_text or "BREAKING-CHANGE:" in full_text:
        breaking = True
    return conv_type, conv_scope, breaking


def _is_promisor_partial_clone(repo_path: Path) -> bool:
    """Detect whether the repository is a partial/blobless clone (`--filter=blob:none`)."""
    proc = run_git_command(repo_path, ["config", "--get", "remote.origin.promisor"], timeout=3, check=False)
    return proc.returncode == 0 and proc.stdout.strip().lower() == "true"


def _parse_commits_log(repo_path: Path, rev_spec: str | list[str], max_count: int = 50) -> list[CommitSummaryItem]:
    """Parse git log with NUL-delimited fields and numstat (or tree-only name-only on blobless clones) per commit."""
    rev_args = [rev_spec] if isinstance(rev_spec, str) else list(rev_spec)
    commits: list[CommitSummaryItem] = []

    fmt2 = "==COMMIT_START==%n%H%x00%h%x00%an%x00%ae%x00%aI%x00%s%x00%b%x00==META_END=="
    is_partial = _is_promisor_partial_clone(repo_path)
    stat_flag = "--name-only" if is_partial else "--numstat"
    proc2 = run_git_command(
        repo_path,
        [
            "log",
            "--no-show-signature",
            f"--max-count={max_count}",
            f"--format={fmt2}",
            stat_flag,
            "-m",
            "--first-parent",
            *rev_args,
            "--",
        ],
        timeout=15 if not is_partial else 20,
        check=False,
    )
    if (proc2.returncode != 0 or not proc2.stdout.strip()) and not is_partial:
        # Fallback to tree-only --name-only if --numstat timed out on a massive commit range (BUG-028)
        proc2 = run_git_command(
            repo_path,
            [
                "log",
                "--no-show-signature",
                f"--max-count={max_count}",
                f"--format={fmt2}",
                "--name-only",
                "-m",
                "--first-parent",
                *rev_args,
                "--",
            ],
            timeout=20,
            check=False,
        )
    if proc2.returncode != 0:
        stderr_clean = redact_secrets((proc2.stderr or proc2.stdout or "").strip())
        raise AthenaValidationError(
            "GIT_HISTORY_EXTRACTION_FAILED",
            f"Git history extraction failed: {stderr_clean or 'unknown Git error'}",
        )
    if not proc2.stdout.strip():
        return []

    for chunk in proc2.stdout.split("==COMMIT_START==\n"):
        if not chunk.strip() or "==META_END==" not in chunk:
            continue
        meta_part, stat_part = chunk.split("==META_END==", 1)
        fields = meta_part.split("\x00")
        if len(fields) < 7:
            continue
        c_hash, s_hash, a_name, a_email, a_date, subj, body = (
            fields[0].strip(),
            fields[1].strip(),
            fields[2].strip(),
            fields[3].strip(),
            fields[4].strip(),
            redact_secrets(fields[5].strip()),
            redact_secrets(fields[6].strip()),
        )
        changed_files: list[str] = []
        insertions = 0
        deletions = 0
        for line in stat_part.strip().splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                ins_str, del_str, fpath = parts[0], parts[1], parts[2]
                if ins_str.isdigit():
                    insertions += int(ins_str)
                if del_str.isdigit():
                    deletions += int(del_str)
                changed_files.append(fpath.strip())
            else:
                changed_files.append(line_s)
        c_type, c_scope, is_brk = _parse_conventional_commit(subj, body)
        commits.append(
            CommitSummaryItem(
                commit_hash=c_hash,
                short_hash=s_hash,
                author_name=a_name,
                author_email=a_email,
                authored_date=a_date,
                subject=subj,
                body=body,
                changed_files=changed_files,
                insertions=insertions,
                deletions=deletions,
                conventional_type=c_type,
                conventional_scope=c_scope,
                declares_breaking_in_message=is_brk,
            )
        )
    return commits


def inspect_repository_state(repo_path_input: str | Path, max_recent_commits: int = 10) -> RepositoryStatusReport:
    """Inspect a local Git repository safely without modifying any state."""
    try:
        repo_path = validate_repo_path(repo_path_input)
    except AthenaValidationError as exc:
        return RepositoryStatusReport(
            status="error",
            repo_path=str(repo_path_input),
            is_valid_git_repo=False,
            error_code=exc.code,
            error_message=exc.message,
        )

    chk = run_git_command(repo_path, ["rev-parse", "--is-inside-work-tree"], check=False)
    if chk.returncode != 0 or chk.stdout.strip().lower() != "true":
        return RepositoryStatusReport(
            status="error",
            repo_path=str(repo_path),
            is_valid_git_repo=False,
            error_code="NOT_A_GIT_REPOSITORY",
            error_message=f"Directory is not a valid Git repository: {repo_path}",
        )

    shallow_proc = run_git_command(repo_path, ["rev-parse", "--is-shallow-repository"], check=False)
    is_shallow = shallow_proc.returncode == 0 and shallow_proc.stdout.strip().lower() == "true"

    branch_proc = run_git_command(repo_path, ["branch", "--show-current"], check=False)
    current_branch = branch_proc.stdout.strip() or None
    if not current_branch:
        sym_proc = run_git_command(repo_path, ["symbolic-ref", "--short", "HEAD"], check=False)
        current_branch = sym_proc.stdout.strip() or "DETACHED_HEAD"

    branches_proc = run_git_command(
        repo_path, ["for-each-ref", "--format=%(refname:short)", "refs/heads/"], check=False
    )
    branches = [b.strip() for b in branches_proc.stdout.splitlines() if b.strip()]

    tags_proc = run_git_command(repo_path, ["tag", "--sort=-creatordate"], check=False)
    tags = [t.strip() for t in tags_proc.stdout.splitlines() if t.strip()]

    status_proc = run_git_command(repo_path, ["status", "--porcelain=v1", "-uall"], check=False)
    staged: list[str] = []
    unstaged: list[str] = []
    untracked: list[str] = []
    for line in status_proc.stdout.splitlines():
        if len(line) < 4:
            continue
        xy = line[:2]
        fpath = line[3:].strip()
        if xy == "??":
            untracked.append(fpath)
        else:
            if xy[0] not in (" ", "?"):
                staged.append(fpath)
            if xy[1] not in (" ", "?"):
                unstaged.append(fpath)

    head_verify = run_git_command(repo_path, ["rev-parse", "--verify", "HEAD"], check=False)
    if head_verify.returncode != 0:
        return RepositoryStatusReport(
            status="ok",
            repo_path=str(repo_path),
            is_valid_git_repo=True,
            is_empty_repo=True,
            is_shallow_repo=is_shallow,
            current_branch=current_branch,
            branches=branches,
            tags=tags,
            working_tree_clean=(not staged and not unstaged and not untracked),
            staged_files=staged,
            unstaged_files=unstaged,
            untracked_files=untracked,
            recent_commits=[],
        )

    recent_commits = _parse_commits_log(repo_path, "HEAD", max_count=max(1, min(max_recent_commits, 50)))
    return RepositoryStatusReport(
        status="ok",
        repo_path=str(repo_path),
        is_valid_git_repo=True,
        is_empty_repo=False,
        is_shallow_repo=is_shallow,
        current_branch=current_branch,
        head_commit=recent_commits[0] if recent_commits else None,
        branches=branches,
        tags=tags,
        working_tree_clean=(not staged and not unstaged and not untracked),
        staged_files=staged,
        unstaged_files=unstaged,
        untracked_files=untracked,
        recent_commits=recent_commits,
    )


def resolve_revision_sha(repo_path: Path, rev: str, param_name: str) -> str:
    """Validate and resolve a Git revision to its 40-char commit SHA (or 'WORKING_TREE')."""
    cleaned = validate_git_revision(rev, param_name=param_name)
    if cleaned == "WORKING_TREE":
        return "WORKING_TREE"
    if cleaned.upper() == "AUTO":
        # Resolve to the most recent tag reachable from HEAD, or the initial commit if no tags exist
        tag_proc = run_git_command(repo_path, ["describe", "--tags", "--abbrev=0", "HEAD^"], check=False)
        if tag_proc.returncode != 0 or not tag_proc.stdout.strip():
            tag_proc = run_git_command(repo_path, ["describe", "--tags", "--abbrev=0"], check=False)
        if tag_proc.returncode == 0 and tag_proc.stdout.strip():
            tag_name = tag_proc.stdout.strip().splitlines()[0].strip()
            sha_proc = run_git_command(
                repo_path,
                ["rev-parse", "--verify", "--end-of-options", f"{tag_name}^{{commit}}"],
                check=False,
            )
            if sha_proc.returncode == 0 and sha_proc.stdout.strip():
                return sha_proc.stdout.strip()
        # Fallback when repository has no tags: use root commit (or HEAD~1 if root == HEAD is avoided)
        root_proc = run_git_command(repo_path, ["rev-list", "--max-parents=0", "HEAD"], check=False)
        if root_proc.returncode == 0 and root_proc.stdout.strip():
            roots = [r.strip() for r in root_proc.stdout.splitlines() if r.strip()]
            if roots:
                return roots[-1]
    proc = run_git_command(
        repo_path,
        ["rev-parse", "--verify", "--end-of-options", f"{cleaned}^{{commit}}"],
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise AthenaValidationError(
            "REVISION_NOT_FOUND",
            f"Git revision '{cleaned}' ('{param_name}') could not be resolved to a valid commit in {repo_path}.",
        )
    return proc.stdout.strip()


def read_blob_at_revision(repo_path: Path, rev_sha: str, file_path: str) -> str | None:
    """Read source text safely (UTF-8/cp1252/latin-1) at a commit SHA or from WORKING_TREE."""
    norm_path = file_path.replace("\\", "/")
    if rev_sha == "WORKING_TREE":
        candidate = repo_path / norm_path
        if not candidate.exists() or not candidate.is_file():
            return None
        if not is_safe_repo_file(repo_path, candidate):
            return None
        if candidate.stat().st_size > MAX_SOURCE_BLOB_BYTES:
            return None
        try:
            return decode_bytes_safely(candidate.read_bytes())
        except OSError:
            return None

    size_proc = run_git_command(
        repo_path,
        ["cat-file", "-s", f"{rev_sha}:{norm_path}"],
        check=False,
    )
    if size_proc.returncode != 0 or not size_proc.stdout.strip().isdigit():
        return None
    if int(size_proc.stdout.strip()) > MAX_SOURCE_BLOB_BYTES:
        return None

    git_env = _build_git_env()
    try:
        blob_proc = subprocess.run(  # nosec B603
            ["git", "-c", "core.quotePath=false", "cat-file", "blob", f"{rev_sha}:{norm_path}"],
            cwd=str(repo_path),
            shell=False,
            capture_output=True,
            text=False,
            timeout=30,
            env=git_env,
        )
    except subprocess.TimeoutExpired:
        return None
    if blob_proc.returncode != 0:
        return None
    return decode_bytes_safely(blob_proc.stdout)


def read_blobs_at_revision(
    repo_path: Path,
    rev_sha: str,
    file_paths: list[str],
    *,
    max_bytes: int = MAX_SOURCE_BLOB_BYTES,
) -> dict[str, str]:
    """Batch-read multiple source blobs at a commit SHA using two `git cat-file` calls."""
    unique_paths: list[str] = []
    seen: set[str] = set()
    for raw_path in file_paths:
        norm = raw_path.replace("\\", "/")
        if not norm or "\n" in norm or "\r" in norm or "\x00" in norm:
            continue
        if norm not in seen:
            seen.add(norm)
            unique_paths.append(norm)

    if not unique_paths:
        return {}

    result: dict[str, str] = {}
    if rev_sha == "WORKING_TREE":
        for norm in unique_paths:
            candidate = repo_path / norm
            if not candidate.exists() or not candidate.is_file():
                continue
            if not is_safe_repo_file(repo_path, candidate):
                continue
            try:
                if candidate.stat().st_size > max_bytes:
                    continue
                result[norm] = decode_bytes_safely(candidate.read_bytes())
            except OSError:
                continue
        return result

    git_env = _build_git_env()
    specs_bytes = "".join(f"{rev_sha}:{p}\n" for p in unique_paths).encode("utf-8")
    try:
        chk_proc = subprocess.run(  # nosec B603
            ["git", "-c", "core.quotePath=false", "cat-file", "--batch-check"],
            cwd=str(repo_path),
            input=specs_bytes,
            shell=False,
            capture_output=True,
            text=False,
            timeout=30,
            env=git_env,
        )
    except subprocess.TimeoutExpired:
        return {}

    if not chk_proc.stdout:
        return {}

    chk_lines = chk_proc.stdout.splitlines()
    valid_paths: list[str] = []
    for path, raw_line in zip(unique_paths, chk_lines):
        line_str = raw_line.decode("utf-8", errors="replace").strip()
        parts = line_str.rsplit(" ", 2)
        if len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit():
            if int(parts[2]) <= max_bytes:
                valid_paths.append(path)

    if not valid_paths:
        return {}

    batch_input = "".join(f"{rev_sha}:{p}\n" for p in valid_paths).encode("utf-8")
    try:
        batch_proc = subprocess.run(  # nosec B603
            ["git", "-c", "core.quotePath=false", "cat-file", "--batch"],
            cwd=str(repo_path),
            input=batch_input,
            shell=False,
            capture_output=True,
            text=False,
            timeout=30,
            env=git_env,
        )
    except subprocess.TimeoutExpired:
        return {}

    raw_out = batch_proc.stdout
    if not raw_out:
        return {}

    pos = 0
    data_len = len(raw_out)
    for path in valid_paths:
        nl = raw_out.find(b"\n", pos)
        if nl == -1:
            break
        header = raw_out[pos:nl].decode("utf-8", errors="replace").strip()
        pos = nl + 1
        parts = header.rsplit(" ", 2)
        if len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit():
            size = int(parts[2])
            if size <= max_bytes and pos + size <= data_len:
                result[path] = decode_bytes_safely(raw_out[pos : pos + size])
            pos += size + 1
        elif len(parts) >= 3 and parts[-1].isdigit():
            size = int(parts[-1])
            pos += size + 1

    return result


def git_grep_matching_files(
    repo_path: Path,
    rev_sha: str,
    fixed_terms: list[str],
    *,
    regex_patterns: list[str] | None = None,
    timeout: int = 20,
) -> set[str] | None:
    """Prefilter repository paths using fast native `git grep -I -l` at ``rev_sha``.

    Returns matched repository-relative POSIX paths, or ``None`` if prefiltering
    could not be completed reliably so callers can fall back to direct scanning.
    """
    if _is_promisor_partial_clone(repo_path):
        # Never force lazy fetches in blobless partial clones.
        return None

    clean_terms = [
        t
        for t in dict.fromkeys(fixed_terms)
        if t and "\x00" not in t and "\n" not in t and "\r" not in t
    ]
    clean_regex = [
        p
        for p in dict.fromkeys(regex_patterns or ())
        if p and "\x00" not in p and "\n" not in p and "\r" not in p
    ]
    if not clean_terms and not clean_regex:
        return set()

    matched: set[str] = set()
    target_tree_args = [] if rev_sha == "WORKING_TREE" else [rev_sha]
    prefix = f"{rev_sha}:" if rev_sha != "WORKING_TREE" else ""

    def _run_batch(mode_flag: str, patterns: list[str]) -> bool:
        if not patterns:
            return True
        cmd: list[str] = ["grep", "-I", "-l", mode_flag, "-f", "-"]
        if target_tree_args:
            cmd.extend(target_tree_args)
        cmd.append("--")
        proc = run_git_command(
            repo_path,
            cmd,
            timeout=timeout,
            check=False,
            input_text="\n".join(patterns) + "\n",
        )
        if proc.returncode not in (0, 1):
            return False
        if proc.returncode == 0:
            for raw_ln in proc.stdout.splitlines():
                ln = raw_ln.strip()
                if not ln:
                    continue
                if prefix and ln.startswith(prefix):
                    ln = ln[len(prefix) :]
                ln = ln.replace("\\", "/")
                if ln:
                    matched.add(ln)
        return True

    if clean_terms and not _run_batch("-F", clean_terms):
        return None
    if clean_regex and not _run_batch("-E", clean_regex):
        return None
    return matched


def _parse_unified_diff_by_file(diff_text: str) -> dict[str, tuple[list[ParsedHunk], int, int, bool]]:
    """Parse unified git diff output into per-file hunks, insertions, deletions, and binary flags."""
    results: dict[str, tuple[list[ParsedHunk], int, int, bool]] = {}
    max_raw_hunk_chars = MAX_EVIDENCE_EXCERPT_CHARS + 1024
    for file_path, raw_hunks, ins_count, del_count, is_binary in parse_unified_diff_raw(diff_text):
        hunks: list[ParsedHunk] = []
        total_joined_chars = 0
        for header, b_start, b_end, t_start, t_end, raw_lines in raw_hunks:
            if len(hunks) >= 6 and total_joined_chars > MAX_BOUNDED_DIFF_CHARS + 64:
                excerpt = ""
            else:
                bounded_raw = (
                    raw_lines
                    if len(raw_lines) <= max_raw_hunk_chars
                    else raw_lines[:max_raw_hunk_chars]
                )
                excerpt = redact_secrets(bounded_raw)
                if len(excerpt) > MAX_EVIDENCE_EXCERPT_CHARS:
                    excerpt = excerpt[:MAX_EVIDENCE_EXCERPT_CHARS] + "\n... [diff hunk truncated]"
            hunks.append(
                ParsedHunk(
                    header=header,
                    base_span=LineSpan(start_line=b_start, end_line=b_end) if b_start > 0 else None,
                    target_span=LineSpan(start_line=t_start, end_line=t_end) if t_start > 0 else None,
                    excerpt=excerpt,
                )
            )
            total_joined_chars += len(header) + len(excerpt) + 2
        results[file_path] = (hunks, ins_count, del_count, is_binary)
    return results


def extract_revision_range_data(
    repo_path_input: str | Path,
    base_ref: str,
    target_ref: str = "HEAD",
    max_commits: int = 100,
) -> RawRangeExtraction:
    """Extract commits, file diffs, source blobs, and ground-truth EvidenceRecords between two revisions."""
    repo_path = validate_repo_path(repo_path_input)
    chk = run_git_command(repo_path, ["rev-parse", "--is-inside-work-tree"], check=False)
    if chk.returncode != 0 or chk.stdout.strip().lower() != "true":
        raise AthenaValidationError(
            "NOT_A_GIT_REPOSITORY",
            f"Directory is not a valid Git repository: {repo_path}",
        )

    head_verify = run_git_command(repo_path, ["rev-parse", "--verify", "HEAD"], check=False)
    if head_verify.returncode != 0:
        raise AthenaValidationError(
            "EMPTY_REPOSITORY",
            f"Repository has no commits yet: {repo_path}",
        )

    base_sha = resolve_revision_sha(repo_path, base_ref, param_name="base_ref")
    if base_sha == "WORKING_TREE":
        raise AthenaValidationError(
            "INVALID_BASE_REVISION",
            "Parameter 'base_ref' must be a committed revision (tag, branch, or commit SHA), not 'WORKING_TREE'.",
        )
    target_sha = resolve_revision_sha(repo_path, target_ref, param_name="target_ref")

    # Extract commit list between base and target
    if target_sha == "WORKING_TREE":
        commits = _parse_commits_log(repo_path, f"{base_sha}..HEAD", max_count=max_commits)
    elif base_sha == target_sha:
        commits = []
    else:
        commits = _parse_commits_log(repo_path, f"{base_sha}..{target_sha}", max_count=max_commits)

    latest_commit_hash = commits[0].commit_hash if commits else (target_sha if target_sha != "WORKING_TREE" else base_sha)
    latest_commit_msg = commits[0].subject if commits else "Working tree or direct revision comparison"

    # Extract file statuses (omit -M on partial/blobless clones so Git performs a 100% local tree comparison without fetching blobs for rename similarity!)
    is_partial = _is_promisor_partial_clone(repo_path)
    diff_target_args = [base_sha] if target_sha == "WORKING_TREE" else [base_sha, target_sha]
    ns_flags = ["--name-status", "--no-ext-diff", "--no-textconv", "--color=never"]
    if not is_partial:
        ns_flags.insert(1, "-M")
    name_status_proc = run_git_command(
        repo_path,
        [
            "diff",
            *ns_flags,
            "--end-of-options",
            *diff_target_args,
            "--",
        ],
        timeout=30,
        check=True,
    )

    # Pre-collect non-lockfile paths from name_status and rank core production code files first (BUG-031)
    prelim_paths: list[str] = []
    for line in name_status_proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            p = parts[-1].strip().replace("\\", "/")
            if p and not _is_lockfile_or_generated(p):
                prelim_paths.append(p)

    code_exts = (
        ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".go", ".rs", ".java", ".kt", ".scala", ".cs", ".rb", ".php", ".swift",
    )
    aux_prefixes = (
        "benchmark", "example", "sample", "script", "maint/",
        ".github/", "features/", "demo", "tools/", "fuzz/",
    )

    def _path_priority_key(p: str) -> tuple[int, str]:
        low = p.lower()
        is_code = low.endswith(code_exts)
        is_test = _is_test_file(p)
        is_doc = _is_doc_file(p)
        if is_code and not is_test and not is_doc:
            is_aux = any(low.startswith(pref) or f"/{pref}" in low for pref in aux_prefixes)
            return (1 if is_aux else 0, p)
        if is_doc:
            return (2, p)
        if is_code and is_test:
            return (3, p)
        return (4, p)

    sorted_prelim = sorted(prelim_paths, key=_path_priority_key)
    max_ast_blob_files = 25 if is_partial else 80
    selected_ast_code_paths = set(
        [
            p
            for p in sorted_prelim
            if p.endswith(code_exts) and not _is_test_file(p) and not _is_doc_file(p)
        ][:max_ast_blob_files]
    )

    diff_flags = [
        "--ignore-cr-at-eol",
        "--no-ext-diff",
        "--no-textconv",
        "--color=never",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "-U3",
    ]
    if not is_partial:
        diff_flags.append("-M")
        path_filter_args: list[str] = []
    else:
        # Ensure all selected AST code files plus top doc/test files are fetched in the single batch git diff
        path_filter_args = sorted_prelim[:35]

    # Run spoof-proof unified diff (with 3 lines of context so hunks are human/LLM readable)
    if is_partial and not path_filter_args:
        parsed_diffs: dict[str, tuple[list[ParsedHunk], int, int, bool]] = {}
    else:
        full_diff_proc = run_git_command(
            repo_path,
            [
                "diff",
                *diff_flags,
                "--end-of-options",
                *diff_target_args,
                *(["--", *path_filter_args] if path_filter_args else ["--"]),
            ],
            timeout=25,
            check=True,
        )
        parsed_diffs = _parse_unified_diff_by_file(full_diff_proc.stdout)
    batched_partial_paths = set(path_filter_args)

    evidence_registry: dict[str, EvidenceRecord] = {}
    working_tree_stats: dict[str, tuple[int, int]] = {}
    ev_counter = 1

    def _next_ev_id() -> str:
        nonlocal ev_counter
        eid = f"ev_{ev_counter:03d}"
        ev_counter += 1
        return eid

    # Map file -> most recent commit touching it in range
    file_to_commit: dict[str, tuple[str, str]] = {}
    for c in commits:
        for fpath in c.changed_files:
            norm_f = fpath.replace("\\", "/")
            if norm_f not in file_to_commit:
                file_to_commit[norm_f] = (c.commit_hash, c.subject)

    changed_files: list[ChangedFileDelta] = []
    base_blobs: dict[str, str] = {}
    target_blobs: dict[str, str] = {}
    pending_base_reads: list[tuple[str, str]] = []
    pending_target_reads: list[str] = []
    for line in name_status_proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        code = parts[0].strip()
        old_path: str | None = None
        if code.startswith("R") and len(parts) >= 3:
            old_path = parts[1].strip().replace("\\", "/")
            file_path = parts[2].strip().replace("\\", "/")
            status_lit = "renamed"
        elif code.startswith("A"):
            file_path = parts[1].strip().replace("\\", "/")
            status_lit = "added"
        elif code.startswith("D"):
            file_path = parts[1].strip().replace("\\", "/")
            status_lit = "deleted"
        else:
            file_path = parts[1].strip().replace("\\", "/")
            status_lit = "modified"

        c_hash, c_subj = file_to_commit.get(file_path, (latest_commit_hash, latest_commit_msg))

        if _is_lockfile_or_generated(file_path):
            eid = _next_ev_id()
            evidence_registry[eid] = EvidenceRecord(
                evidence_id=eid,
                commit_hash=c_hash,
                commit_message=c_subj,
                file_path=file_path,
                reason_supports_finding=f"Lockfile or generated artifact ({status_lit}); excluded from deep AST/LLM diffing to prevent context bloat.",
                confidence="high",
            )
            changed_files.append(
                ChangedFileDelta(
                    file_path=file_path,
                    old_path=old_path,
                    status="skipped_large_or_lockfile",
                    is_test_file=_is_test_file(file_path),
                    is_doc_file=_is_doc_file(file_path),
                    evidence_ids=[eid],
                )
            )
            continue

        hunks, ins, dels, is_bin = parsed_diffs.get(file_path, ([], 0, 0, False))
        if is_bin:
            eid = _next_ev_id()
            evidence_registry[eid] = EvidenceRecord(
                evidence_id=eid,
                commit_hash=c_hash,
                commit_message=c_subj,
                file_path=file_path,
                reason_supports_finding="Binary file modified in revision range.",
                confidence="high",
            )
            changed_files.append(
                ChangedFileDelta(
                    file_path=file_path,
                    old_path=old_path,
                    status="binary",
                    is_test_file=_is_test_file(file_path),
                    is_doc_file=_is_doc_file(file_path),
                    evidence_ids=[eid],
                )
            )
            continue

        file_ev_ids: list[str] = []
        for hunk in hunks[:6]:  # Bound per-file hunk evidence records
            eid = _next_ev_id()
            evidence_registry[eid] = EvidenceRecord(
                evidence_id=eid,
                commit_hash=c_hash,
                commit_message=c_subj,
                file_path=file_path,
                base_line_span=hunk.base_span,
                target_line_span=hunk.target_span,
                diff_hunk_header=hunk.header,
                diff_excerpt=hunk.excerpt,
                reason_supports_finding=f"Diff hunk in {file_path} ({status_lit}) at {hunk.header}.",
                confidence="high",
            )
            file_ev_ids.append(eid)

        if not file_ev_ids:
            eid = _next_ev_id()
            crlf_or_mode_only = status_lit == "modified" and ins == 0 and dels == 0
            evidence_registry[eid] = EvidenceRecord(
                evidence_id=eid,
                commit_hash=c_hash,
                commit_message=c_subj,
                file_path=file_path,
                reason_supports_finding=(
                    f"File {file_path} had line-ending (CRLF/LF) or file-mode changes only (zero semantic diff)."
                    if crlf_or_mode_only
                    else f"File {file_path} was {status_lit} in revision range."
                ),
                confidence="high",
            )
            file_ev_ids.append(eid)

        joined_diff = "\n".join(f"{h.header}\n{h.excerpt}" for h in hunks)
        if len(joined_diff) > MAX_BOUNDED_DIFF_CHARS:
            joined_diff = joined_diff[:MAX_BOUNDED_DIFF_CHARS] + "\n... [file diff bounded]"

        # Read source blobs only for prioritized non-test code files with real line deltas (BUG-031 / CRLF guard)
        can_load_ast_blob = (
            file_path in selected_ast_code_paths
            and (not is_partial or file_path in batched_partial_paths)
            and not (status_lit == "modified" and ins == 0 and dels == 0 and not hunks)
        )
        if can_load_ast_blob:
            if status_lit in ("modified", "deleted", "renamed"):
                base_lookup_path = old_path or file_path
                pending_base_reads.append((file_path, base_lookup_path))
            if status_lit in ("added", "modified", "renamed"):
                if target_sha == "WORKING_TREE":
                    wt_candidate = repo_path / file_path
                    if wt_candidate.exists() and wt_candidate.is_file() and is_safe_repo_file(repo_path, wt_candidate):
                        try:
                            st = wt_candidate.stat()
                            if st.st_size <= MAX_SOURCE_BLOB_BYTES:
                                target_blobs[file_path] = decode_bytes_safely(wt_candidate.read_bytes())
                                working_tree_stats[file_path] = (st.st_mtime_ns, st.st_size)
                        except OSError:
                            pass
                else:
                    pending_target_reads.append(file_path)

        changed_files.append(
            ChangedFileDelta(
                file_path=file_path,
                old_path=old_path,
                status=status_lit,  # type: ignore[arg-type]
                insertions=ins,
                deletions=dels,
                is_test_file=_is_test_file(file_path),
                is_doc_file=_is_doc_file(file_path),
                hunk_headers=[h.header for h in hunks],
                bounded_diff=joined_diff,
                evidence_ids=file_ev_ids,
            )
        )

    if pending_base_reads:
        batch_base = read_blobs_at_revision(
            repo_path,
            base_sha,
            [lookup for _, lookup in pending_base_reads],
        )
        for file_path, lookup in pending_base_reads:
            b_blob = batch_base.get(lookup)
            if b_blob is not None:
                base_blobs[file_path] = b_blob

    if pending_target_reads and target_sha != "WORKING_TREE":
        batch_target = read_blobs_at_revision(repo_path, target_sha, pending_target_reads)
        for file_path in pending_target_reads:
            t_blob = batch_target.get(file_path)
            if t_blob is not None:
                target_blobs[file_path] = t_blob

    return RawRangeExtraction(
        repo_path=repo_path,
        base_ref=base_ref,
        target_ref=target_ref,
        resolved_base_sha=base_sha,
        resolved_target_sha=target_sha,
        commits=commits,
        changed_files=changed_files,
        base_blobs=base_blobs,
        target_blobs=target_blobs,
        evidence_registry=evidence_registry,
        working_tree_stats=working_tree_stats,
    )

