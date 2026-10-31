"""Partition manifest_500.json into 5 chunks of 100 repos each."""

import json
from pathlib import Path

manifest_path = Path("tests/evaluation/manifest_500.json")
repos = json.loads(manifest_path.read_text(encoding="utf-8"))

chunk_dir = Path("tests/evaluation/chunks")
chunk_dir.mkdir(parents=True, exist_ok=True)

for i in range(5):
    start = i * 100
    end = (i + 1) * 100
    chunk = repos[start:end]
    chunk_file = chunk_dir / f"chunk_{i+1}_of_5.json"
    chunk_file.write_text(json.dumps(chunk, indent=2), encoding="utf-8")
    min_s = min(r["stars_at_collection"] for r in chunk)
    max_s = max(r["stars_at_collection"] for r in chunk)
    tot_s = sum(r["stars_at_collection"] for r in chunk)
    print(f"Chunk {i+1} (repos {start+1}-{end}): {len(chunk)} repos | {tot_s:,} total stars | range: {min_s:,} to {max_s:,}")
