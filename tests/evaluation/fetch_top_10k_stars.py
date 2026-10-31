"""Fetch top repos with >=10,000 stars in pages of 100 using rate-limit backoff."""

import json
import time
import urllib.request
import urllib.error
from pathlib import Path

API_URL = "https://api.github.com/search/repositories?q=stars:%3E=10000+archived:false+fork:false&sort=stars&order=desc&per_page=100&page="

headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "athena-scale-evaluator",
}

all_repos = []

for page in range(1, 6):
    url = API_URL + str(page)
    print(f"Fetching page {page} of top 10k+ repos...")
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                items = data.get("items", [])
                for it in items:
                    all_repos.append({
                        "owner_repo": it["full_name"],
                        "url": it["html_url"],
                        "primary_language": it.get("language") or "Unknown",
                        "stars_at_collection": it["stargazers_count"],
                        "default_branch": it.get("default_branch", "main"),
                        "description": (it.get("description") or "")[:200],
                    })
                print(f"Page {page}: retrieved {len(items)} repos (total so far: {len(all_repos)})")
                break
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                print(f"Rate limited (HTTP {e.code}). Sleeping 30s...")
                time.sleep(30)
            else:
                print(f"HTTP error {e.code}: {e}")
                break
    time.sleep(2)

out_file = Path("tests/evaluation/manifest_500.json")
out_file.write_text(json.dumps(all_repos, indent=2), encoding="utf-8")
print(f"Successfully saved {len(all_repos)} verified >=10,000 star repositories to {out_file}")
