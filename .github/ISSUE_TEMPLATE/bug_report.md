---
name: Bug Report / AST Edge Case
about: Report a false negative, false positive, or runtime error in Athena's Git or AST analysis
title: "[BUG] "
labels: ["bug"]
assignees: []
---

## Summary
A concise description of the bug or AST/Git edge case.

## Minimal Reproduction (Before vs. After Signature / Diff)
If reporting an AST or breaking-change false negative/positive, provide the minimal `base` and `target` code:

```python
# Base version (old)
def example(a, b=2):
    return (a, b)

# Target version (new)
def example(a, inserted=0, b=2):
    return (a, b)
```

## Expected Behavior
What should Athena report (e.g., `is_breaking_candidate=True`, `severity="high"`, specific caller blast-radius)?

## Actual Behavior
What did Athena actually report, or what traceback occurred?

## Environment
- **Athena Commit SHA**: (e.g., `git rev-parse HEAD`)
- **Python Version**: (e.g., `Python 3.13` / `3.14` / `3.15`)
- **OS**: (e.g., Windows / Linux / macOS)
- **Operating Mode**: Mode A (Deterministic) / Mode B (Ollama `gemma:7b` or `qwen2.5-coder:7b`)
