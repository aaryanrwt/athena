"""Scalable, resumable Athena evaluation over many repositories.

Each repo is evaluated in an isolated worker subprocess (hard timeout, process-tree kill, own temp
dir that is always deleted) so a crash/hang/huge repo cannot take down the run or fill the disk.
Results are appended one JSON object per line to a ledger (JSONL); re-running skips repos that
already have a terminal record (use --retry-failed to redo failures).

Reuses `evaluate_single_repo` from run_evaluation.py (same 4 tool checks over the last N commits).

Examples:
    python run_scale_evaluation.py --manifest manifest_scale.json --workers 3 --limit 1500
    python run_scale_evaluation.py --manifest manifest_scale.json --llm --ollama-model gemma:latest \
        --sample 100 --ledger cache/scale/ledger_gemma.jsonl
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
RESULT_MARK = "@@ATHENA_RESULT@@"
TERMINAL = {"passed", "insufficient_history", "failed", "timeout", "crashed"}


def _rmtree(path: Path) -> None:
    def onerr(func, p, *_):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass

    for _ in range(3):
        if not path.exists():
            return
        try:
            if sys.version_info >= (3, 12):
                shutil.rmtree(path, onexc=onerr)
            else:
                shutil.rmtree(path, onerror=onerr)
        except Exception:
            pass
        time.sleep(0.2)


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
        else:
            proc.kill()
    except Exception:
        proc.kill()


def load_ledger(path: Path) -> dict[str, dict[str, Any]]:
    """Last record per repo wins; corrupt/partial lines (e.g. from a hard stop) are ignored."""
    out: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
            out[rec["owner_repo"]] = rec
        except (ValueError, KeyError):
            continue
    return out


def select_pending(
    repos: list[dict[str, Any]], ledger: dict[str, dict[str, Any]], retry_failed: bool = False
) -> list[dict[str, Any]]:
    pending = []
    for r in repos:
        rec = ledger.get(r["owner_repo"])
        if rec is None:
            pending.append(r)
        elif retry_failed and rec.get("status") in ("failed", "timeout", "crashed"):
            pending.append(r)
    return pending


def classify(res: dict[str, Any]) -> str:
    ov = res.get("overall_result")
    if ov == "passed":
        return "passed"
    if ov == "insufficient_history":
        return "insufficient_history"
    return "failed"


def worker_main(args: argparse.Namespace) -> int:
    """Runs in the child process: evaluate one repo, print result JSON on a marked line."""
    sys.path.insert(0, str(HERE))
    import run_evaluation
    from run_evaluation import evaluate_single_repo  # heavy import kept in the child

    def full_blob_clone(url: str, dest_dir: Path, depth: int = 150, timeout: int = 240) -> bool:
        # Athena disables git lazy-fetching, so blob-filtered (partial) clones cannot be diffed.
        # Use a plain shallow clone that contains all blobs for the cloned commits.
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="echo")
        cmd = ["git", "clone", f"--depth={depth}", "--no-tags", "--single-branch", url, str(dest_dir)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, env=env, text=True)
        try:
            proc.communicate(timeout=timeout)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            return False

    run_evaluation._shallow_clone_repo = full_blob_clone
    meta = json.loads(args.worker)
    res = evaluate_single_repo(
        meta,
        timeout=args.clone_timeout,
        clone_depth=args.clone_depth,
        target_commits=args.commits,
        cache_dir=None,
        use_llm=args.llm,
        ollama_model=args.ollama_model,
    )
    print(RESULT_MARK + json.dumps(res), flush=True)
    return 0


def evaluate_isolated(meta: dict[str, Any], args: argparse.Namespace, work_root: Path) -> dict[str, Any]:
    slug = meta["owner_repo"].replace("/", "__")
    work = work_root / slug
    _rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({"TMP": str(work), "TEMP": str(work), "TMPDIR": str(work), "PYTHONIOENCODING": "utf-8"})
    src = str(HERE.parent.parent / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        sys.executable, str(Path(__file__).resolve()), "--worker", json.dumps(meta),
        "--clone-timeout", str(args.clone_timeout), "--clone-depth", str(args.clone_depth),
        "--commits", str(args.commits), "--ollama-model", args.ollama_model,
    ]
    if args.llm:
        cmd.append("--llm")
    t0 = time.time()
    rec: dict[str, Any] = {"owner_repo": meta["owner_repo"], "stars_at_collection": meta.get("stars_at_collection"),
                           "primary_language": meta.get("primary_language")}
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                env=env, text=True, encoding="utf-8", errors="replace")
        try:
            out, err = proc.communicate(timeout=args.repo_timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            try:
                proc.communicate(timeout=10)
            except Exception:
                pass
            rec.update(status="timeout", failure_reason=f"exceeded {args.repo_timeout}s per-repo timeout")
        else:
            line = next((l for l in reversed(out.splitlines()) if l.startswith(RESULT_MARK)), None)
            if line is None:
                tail = (err or out or "").strip().splitlines()[-3:]
                rec.update(status="crashed", exit_code=proc.returncode,
                           failure_reason="worker exited without result: " + " | ".join(tail)[:500])
            else:
                res = json.loads(line[len(RESULT_MARK):])
                rec.update(res)
                rec["status"] = classify(res)
    except Exception as exc:  # noqa: BLE001
        rec.update(status="crashed", failure_reason=f"{type(exc).__name__}: {exc}")
    finally:
        _rmtree(work)
    rec["wall_seconds"] = round(time.time() - t0, 2)
    rec["mode"] = f"ollama:{args.ollama_model}" if args.llm else "deterministic"
    rec["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    return rec


def run(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    manifest = [r for r in manifest if r.get("stars_at_collection", 0) >= args.min_stars]
    manifest.sort(key=lambda r: r.get("stars_at_collection", 0), reverse=True)
    if args.sample:
        rng = random.Random(args.seed)
        manifest = sorted(rng.sample(manifest, min(args.sample, len(manifest))),
                          key=lambda r: r.get("stars_at_collection", 0), reverse=True)
    if args.limit:
        manifest = manifest[: args.limit]

    ledger_path = Path(args.ledger)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger = load_ledger(ledger_path)
    pending = select_pending(manifest, ledger, args.retry_failed)
    work_root = Path(args.work_dir)
    work_root.mkdir(parents=True, exist_ok=True)
    print(f"manifest={len(manifest)} already_done={len(manifest) - len(pending)} pending={len(pending)} "
          f"workers={args.workers} mode={'ollama:' + args.ollama_model if args.llm else 'deterministic'}", flush=True)

    lock = threading.Lock()
    done = 0
    t_start = time.time()

    def task(meta: dict[str, Any]) -> None:
        nonlocal done
        rec = evaluate_isolated(meta, args, work_root)
        with lock:
            with ledger_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
                f.flush()
                os.fsync(f.fileno())
            done += 1
            print(f"[{done}/{len(pending)}] {rec['owner_repo']} {rec['status']} {rec['wall_seconds']}s "
                  f"elapsed={time.time() - t_start:.0f}s", flush=True)

    try:
        with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
            list(ex.map(task, pending))
    except KeyboardInterrupt:
        print("Interrupted; ledger is consistent. Re-run the same command to resume.", flush=True)
        return 130
    print(f"finished {done} repos in {time.time() - t_start:.0f}s -> {ledger_path}", flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=str(HERE / "manifest_scale.json"))
    ap.add_argument("--ledger", default=str(HERE / "cache" / "scale" / "scale_ledger.jsonl"))
    ap.add_argument("--work-dir", default=str(HERE / "cache" / "scale_work"))
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0, help="Only the top-N repos by stars.")
    ap.add_argument("--sample", type=int, default=0, help="Random sample of N repos (seeded).")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--min-stars", type=int, default=10000)
    ap.add_argument("--commits", type=int, default=100, help="History depth to analyze.")
    ap.add_argument("--clone-depth", type=int, default=150)
    ap.add_argument("--clone-timeout", type=int, default=240)
    ap.add_argument("--repo-timeout", type=int, default=600, help="Hard per-repo wall limit (s).")
    ap.add_argument("--retry-failed", action="store_true")
    ap.add_argument("--llm", action="store_true", help="Use local Ollama for narrative generation.")
    ap.add_argument("--ollama-model", default="qwen2.5-coder:7b")
    ap.add_argument("--worker", help=argparse.SUPPRESS)
    return ap


if __name__ == "__main__":
    a = build_parser().parse_args()
    raise SystemExit(worker_main(a) if a.worker else run(a))
