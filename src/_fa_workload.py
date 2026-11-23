"""Thin launcher in src/ so `fast-anything` resolves package imports as `athena.*`."""

from __future__ import annotations

import runpy
from pathlib import Path

if __name__ == "__main__":
    script = Path(__file__).resolve().parents[1] / "scripts" / "bench_workload.py"
    runpy.run_path(str(script), run_name="__main__")
