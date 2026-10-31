# GitHub Action, Docker, and pre-commit

## GitHub Action: sticky PR comment

Athena ships a composite action ([`action.yml`](../action.yml)) that runs
`athena breaking-changes` between the PR base and head and posts **one** comment
per PR. The comment carries a hidden marker (`<!-- athena-breaking-changes -->`),
so reruns update it instead of adding new ones.

```yaml
name: Athena
on:
  pull_request:

permissions:
  contents: read

jobs:
  athena:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # only needed for the sticky comment
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0              # Athena needs history for base..head
          persist-credentials: false
      - uses: aaryanrwt/athena@main   # pin to a release tag or full SHA once released
```

Inputs: `base`, `target`, `install-source` (`git` default, or `local` to install
the checked-out ref), `ref`, `python-version`, `working-directory`,
`comment`, `fail-on-breaking`, `github-token`. Output: `breaking-changes` (count).

### `pull_request` vs `pull_request_target`

- **Use `pull_request` (default, recommended).** The PR's code runs with a
  read-only token on forks, so untrusted code cannot write to your repository.
  On fork PRs the action skips the comment (the token cannot write) and writes
  the report to the job summary instead.
- **Avoid `pull_request_target`.** It runs with a write token and secrets. Never
  check out or install the PR head in such a job. If you need comments on fork
  PRs, run Athena in an unprivileged `pull_request` job, upload the rendered
  comment as an artifact, and post it from a separate `workflow_run` job that
  checks out nothing from the PR.
- Grant `pull-requests: write` only to the job that comments; keep the rest at
  `contents: read`. The action passes inputs through environment variables and
  never interpolates them into shell code.

## Docker

```bash
docker build -t athena .
docker run --rm -v "$PWD:/repo" athena breaking-changes /repo --base main --target HEAD
```

The image is based on `python:3.12-slim`, includes `git`, runs as a non-root
user, and uses `athena` as the entrypoint.

## pre-commit

```yaml
repos:
  - repo: https://github.com/aaryanrwt/athena
    rev: v1.2.0   # use the latest release tag
    hooks:
      - id: athena-check
```

The hook runs `athena check --staged`.

## Maintainer setup

### GitHub Release & Version Tagging

1. Tag a release commit (for example `git tag v1.2.0 && git push origin v1.2.0`).
2. Create a GitHub Release with release notes generated via `athena release-notes`.

### GitHub Marketplace listing

1. Make sure `action.yml` is at the repository root and the repository is public.
2. Tag a release (for example `v1.2.0`) and move a major tag (`v1`) to it.
3. On the release page choose *Publish this Action to the GitHub Marketplace*,
   pick a category, and accept the Marketplace developer agreement.
