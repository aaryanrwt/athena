# Athena v1.2.0 Multi-Language 100+ Commit & MCP Evaluation Report (`gemma:latest` & `qwen2.5-coder:7b`)

- **Execution Timestamp**: `2026-10-20 17:57:06Z`
- **Evaluation Mode**: `Mode B (Hybrid Local Ollama dual + Deterministic Engine)`
- **Maintainer & Owner**: Aaryan Rawat (`aaryan28rwt@gmail.com`)
- **Manifest Corpus**: `55` actively maintained repositories (`1,558,900` cumulative GitHub stars, `55` with `>=10,000+` stars)
- **Total Repositories Cloned & Evaluated via MCP**: `55`
- **Cumulative GitHub Stars of Evaluated Repositories**: `1,558,900` stars
- **Repositories with >= 100 Commits Inspected**: `55` (`>= 50` commits: `55`)
- **Repositories with >= 10,000 GitHub Stars Evaluated**: `55`
- **Total Commits Inspected Across Corpus**: `5,500`
- **Total Diff Hunks Processed**: `10,680`
- **Total Recursive Functions Analyzed (Multi-Language)**: `411`
- **Passed Deep-History & Full MCP Tool Suite Evaluation**: `55` (100.0%)
- **Insufficient History**: `0`
- **Failed / Timed Out**: `0`
- **Average Duration per Repository**: `45.26s`

## 1. Multi-Language 100+ Commit & Full MCP Tool Suite Methodology

Under the Athena v1.2.0 evaluation protocol:
1. **Bounded 100+ Commit History (`--depth=125`, `--filter=blob:none`)**: Each repository is cloned into `tests/evaluation/cache` with at least 100 reachable ancestor commits (`HEAD~100..HEAD`).
2. **Full MCP Server Execution**: Every repository is evaluated through Athena's MCP tools (`inspect_repository`, `analyze_git_history`, `detect_potential_breaking_changes`, and `generate_release_notes`).
3. **Multi-Language Structural & AST Blast-Radius Inspection**: Analyzes structural symbol signatures across Python, TypeScript, JavaScript, C++, C, Go, Rust, Java, C#, Ruby, and PHP, plus recursive function bugs (`is_recursive`), public API export boundaries, and dynamic dispatch calls.
4. **Dual Local Ollama Models Verified (`gemma:latest` & `qwen2.5-coder:7b`)**: Both `gemma:latest` (Gemma 7B, `a72c7f4d0a15`, 5.0 GB) and `qwen2.5-coder:7b` (`dae161e27b0e`, 4.7 GB) are executed with automatic citation verification and deterministic fallback.

## 2. Comprehensive Repository Results Table

| Repository | Language | Stars | >=10k | Range Tested | Total Commits | Inspected | Diffs | Files | Struct Files | Rec Fns | AST Symbols | Breaking | MCP Tools | LLM Backend | Result | Duration |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `colinhacks/zod` | TypeScript | 35,000 | YES | `3195ed01..afdac65e` | 100 | 100 | 153 | 227 | 172 | 6 | 40 | 0 | 4/4 OK | `ollama:gemma:latest` | **PASSED** | 84.16s |
| `rollup/rollup` | JavaScript | 25,500 | YES | `4b6bc39e..e70c19b9` | 100 | 100 | 87 | 445 | 353 | 0 | 21 | 8 | 4/4 OK | `ollama:gemma:latest` | **PASSED** | 89.23s |
| `pytest-dev/pytest` | Python | 12,200 | YES | `a3a62a0e..49ea4d08` | 222 | 100 | 242 | 174 | 87 | 11 | 30 | 19 | 4/4 OK | `ollama:gemma:latest` | **PASSED** | 73.18s |
| `nlohmann/json` | C++ | 43,500 | YES | `0c446267..4da932f5` | 100 | 100 | 1146 | 311 | 141 | 25 | 191 | 18 | 4/4 OK | `ollama:qwen2.5-coder:7b` | **PASSED** | 64.36s |
| `DaveGamble/cJSON` | C | 11,200 | YES | `98ecc024..6d9f2443` | 133 | 100 | 150 | 31 | 15 | 5 | 1 | 0 | 4/4 OK | `ollama:qwen2.5-coder:7b` | **PASSED** | 41.32s |
| `gin-gonic/gin` | Go | 79,500 | YES | `58135f06..0f09c3a9` | 100 | 100 | 188 | 59 | 43 | 6 | 30 | 5 | 4/4 OK | `ollama:qwen2.5-coder:7b` | **PASSED** | 54.82s |
| `tokio-rs/tokio` | Rust | 27,500 | YES | `decfd115..ce685ee6` | 270 | 100 | 87 | 268 | 248 | 16 | 44 | 1 | 4/4 OK | `deterministic_engine` | **PASSED** | 50.95s |
| `ReactiveX/RxJava` | Java | 48,000 | YES | `c027d005..ee4a29e1` | 104 | 100 | 101 | 205 | 183 | 40 | 45 | 10 | 4/4 OK | `deterministic_engine` | **PASSED** | 48.32s |
| `DapperLib/Dapper` | C# | 17,800 | YES | `02c92d99..eb47546a` | 102 | 100 | 228 | 166 | 109 | 7 | 42 | 13 | 4/4 OK | `deterministic_engine` | **PASSED** | 26.79s |
| `jekyll/jekyll` | Ruby | 49,500 | YES | `0f03b31b..97c3bdc8` | 100 | 100 | 50 | 82 | 26 | 1 | 7 | 1 | 4/4 OK | `deterministic_engine` | **PASSED** | 13.76s |
| `guzzle/guzzle` | PHP | 23,300 | YES | `7e93caca..b920e5fc` | 167 | 100 | 342 | 105 | 86 | 13 | 230 | 13 | 4/4 OK | `deterministic_engine` | **PASSED** | 20.0s |
| `trpc/trpc` | TypeScript | 35,500 | YES | `cdbc2804..1c9bf51e` | 100 | 100 | 95 | 479 | 367 | 7 | 25 | 1 | 4/4 OK | `deterministic_engine` | **PASSED** | 64.39s |
| `sveltejs/svelte` | JavaScript | 80,500 | YES | `f2648b35..40bb0848` | 100 | 100 | 76 | 381 | 220 | 12 | 16 | 3 | 4/4 OK | `deterministic_engine` | **PASSED** | 88.7s |
| `aio-libs/aiohttp` | Python | 15,200 | YES | `7577ad38..72a735c6` | 297 | 100 | 123 | 140 | 49 | 2 | 70 | 5 | 4/4 OK | `deterministic_engine` | **PASSED** | 47.63s |
| `gabime/spdlog` | C++ | 25,000 | YES | `6fa36017..76d45805` | 100 | 100 | 128 | 151 | 137 | 2 | 16 | 6 | 4/4 OK | `deterministic_engine` | **PASSED** | 22.64s |
| `libuv/libuv` | C | 24,500 | YES | `972e78f9..bbd08cc8` | 100 | 100 | 108 | 111 | 87 | 5 | 8 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 32.9s |
| `gofiber/fiber` | Go | 34,500 | YES | `eb6e578f..4c6841b3` | 422 | 100 | 139 | 232 | 148 | 3 | 74 | 6 | 4/4 OK | `deterministic_engine` | **PASSED** | 41.75s |
| `serde-rs/serde` | Rust | 10,100 | YES | `e3eaa6a3..0db9b3b5` | 208 | 100 | 153 | 103 | 68 | 1 | 40 | 8 | 4/4 OK | `deterministic_engine` | **PASSED** | 35.69s |
| `TanStack/query` | TypeScript | 43,000 | YES | `c10c1f77..90e331de` | 100 | 100 | 84 | 266 | 65 | 5 | 2 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 58.41s |
| `SortableJS/Sortable` | JavaScript | 29,500 | YES | `2ca1ff5f..48b626bb` | 136 | 100 | 483 | 50 | 25 | 5 | 40 | 17 | 4/4 OK | `deterministic_engine` | **PASSED** | 27.62s |
| `tornadoweb/tornado` | Python | 21,800 | YES | `9660edad..170cf414` | 304 | 100 | 675 | 122 | 82 | 3 | 84 | 80 | 4/4 OK | `deterministic_engine` | **PASSED** | 52.48s |
| `fmtlib/fmt` | C++ | 21,000 | YES | `0cf9f5c9..0fc31633` | 100 | 100 | 155 | 53 | 35 | 20 | 415 | 8 | 4/4 OK | `deterministic_engine` | **PASSED** | 25.39s |
| `lz4/lz4` | C | 10,600 | YES | `9da37b2e..1deef0b7` | 272 | 100 | 267 | 70 | 31 | 23 | 60 | 9 | 4/4 OK | `deterministic_engine` | **PASSED** | 29.12s |
| `spf13/cobra` | Go | 38,500 | YES | `66b215ba..adbc8813` | 105 | 100 | 227 | 40 | 23 | 9 | 26 | 8 | 4/4 OK | `deterministic_engine` | **PASSED** | 12.02s |
| `BurntSushi/ripgrep` | Rust | 50,000 | YES | `5748f81b..3fce3b5b` | 100 | 100 | 157 | 69 | 40 | 10 | 204 | 5 | 4/4 OK | `deterministic_engine` | **PASSED** | 24.42s |
| `pmndrs/zustand` | TypeScript | 49,000 | YES | `a124d59c..d7a5583c` | 100 | 100 | 65 | 75 | 15 | 1 | 2 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 12.27s |
| `highlightjs/highlight.js` | JavaScript | 24,000 | YES | `40fc89ef..fc3f0639` | 100 | 100 | 284 | 282 | 49 | 6 | 1 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 38.88s |
| `scrapy/scrapy` | Python | 53,500 | YES | `eb744fe9..e1111a0f` | 100 | 100 | 193 | 246 | 209 | 1 | 30 | 6 | 4/4 OK | `deterministic_engine` | **PASSED** | 58.19s |
| `catchorg/Catch2` | C++ | 19,000 | YES | `b670de4f..08092139` | 100 | 100 | 322 | 182 | 133 | 11 | 71 | 34 | 4/4 OK | `deterministic_engine` | **PASSED** | 42.09s |
| `nothings/stb` | C | 27,500 | YES | `7a69424f..a7d4c217` | 347 | 100 | 473 | 76 | 47 | 11 | 34 | 5 | 4/4 OK | `deterministic_engine` | **PASSED** | 22.39s |
| `spf13/viper` | Go | 27,500 | YES | `273543ce..528f7416` | 100 | 100 | 135 | 36 | 16 | 3 | 22 | 6 | 4/4 OK | `deterministic_engine` | **PASSED** | 10.94s |
| `sharkdp/bat` | Rust | 50,500 | YES | `f1137453..f748c1a4` | 292 | 100 | 150 | 87 | 28 | 4 | 83 | 3 | 4/4 OK | `deterministic_engine` | **PASSED** | 23.82s |
| `drizzle-team/drizzle-orm` | TypeScript | 25,500 | YES | `7d2ae842..eab8bedb` | 842 | 100 | 141 | 1108 | 850 | 4 | 77 | 7 | 4/4 OK | `deterministic_engine` | **PASSED** | 58.39s |
| `markedjs/marked` | JavaScript | 33,500 | YES | `63a4bba3..2f907438` | 100 | 100 | 107 | 182 | 26 | 4 | 7 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 26.5s |
| `sqlalchemy/sqlalchemy` | Python | 10,200 | YES | `19a6d8f6..ac3deaea` | 134 | 100 | 171 | 162 | 127 | 0 | 33 | 22 | 4/4 OK | `deterministic_engine` | **PASSED** | 141.91s |
| `google/googletest` | C++ | 35,000 | YES | `a35bc769..b66cffcd` | 123 | 100 | 208 | 75 | 55 | 16 | 21 | 3 | 4/4 OK | `deterministic_engine` | **PASSED** | 30.44s |
| `uber-go/zap` | Go | 22,500 | YES | `c50301e9..4892335e` | 100 | 100 | 97 | 105 | 80 | 2 | 56 | 14 | 4/4 OK | `deterministic_engine` | **PASSED** | 25.11s |
| `honojs/hono` | TypeScript | 22,000 | YES | `1096d66e..5ca49b07` | 100 | 100 | 35 | 312 | 245 | 10 | 65 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 31.54s |
| `iamkun/dayjs` | JavaScript | 47,000 | YES | `a78956e8..436bde0b` | 459 | 100 | 59 | 215 | 164 | 5 | 21 | 1 | 4/4 OK | `deterministic_engine` | **PASSED** | 44.85s |
| `PrefectHQ/prefect` | Python | 17,500 | YES | `33327f54..817bc93b` | 100 | 100 | 62 | 377 | 210 | 0 | 4 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 106.76s |
| `google/benchmark` | C++ | 17,200 | YES | `83c826c8..00aed1d2` | 100 | 100 | 88 | 92 | 52 | 5 | 28 | 1 | 4/4 OK | `deterministic_engine` | **PASSED** | 26.13s |
| `vitest-dev/vitest` | TypeScript | 13,500 | YES | `56b319ac..6a5f44eb` | 100 | 100 | 109 | 357 | 259 | 12 | 33 | 3 | 4/4 OK | `deterministic_engine` | **PASSED** | 80.1s |
| `eligrey/FileSaver.js` | JavaScript | 21,500 | YES | `6ad591cc..cea522bc` | 143 | 100 | 14 | 18 | 7 | 0 | 4 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 5.75s |
| `gradio-app/gradio` | Python | 35,000 | YES | `ae892f39..1d6b6cb8` | 100 | 100 | 197 | 558 | 241 | 6 | 71 | 4 | 4/4 OK | `deterministic_engine` | **PASSED** | 130.63s |
| `abseil/abseil-cpp` | C++ | 15,200 | YES | `3dd49353..9fef193a` | 100 | 100 | 237 | 141 | 86 | 8 | 63 | 16 | 4/4 OK | `deterministic_engine` | **PASSED** | 84.65s |
| `reduxjs/redux-toolkit` | TypeScript | 10,900 | YES | `646d54c1..0fd611cc` | 1925 | 100 | 121 | 593 | 310 | 10 | 26 | 12 | 4/4 OK | `deterministic_engine` | **PASSED** | 62.54s |
| `JedWatson/classnames` | JavaScript | 17,500 | YES | `8ec852af..abd63140` | 100 | 100 | 8 | 6 | 0 | 0 | 0 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 6.22s |
| `arrow-py/arrow` | Python | 11,800 | YES | `49624169..2224255c` | 122 | 100 | 437 | 43 | 20 | 0 | 14 | 2 | 4/4 OK | `deterministic_engine` | **PASSED** | 30.53s |
| `pybind/pybind11` | C++ | 16,200 | YES | `50930ae7..fdec8c35` | 100 | 100 | 163 | 173 | 122 | 7 | 91 | 3 | 4/4 OK | `deterministic_engine` | **PASSED** | 41.72s |
| `daybrush/moveable` | TypeScript | 10,200 | YES | `5846e50c..75069102` | 100 | 100 | 141 | 276 | 201 | 7 | 34 | 13 | 4/4 OK | `deterministic_engine` | **PASSED** | 42.32s |
| `benoitc/gunicorn` | Python | 10,000 | YES | `7057fc9f..afc7d2fd` | 275 | 100 | 216 | 284 | 174 | 0 | 68 | 26 | 4/4 OK | `deterministic_engine` | **PASSED** | 57.07s |
| `ocornut/imgui` | C++ | 62,000 | YES | `ed8ed8bb..4be0b47e` | 100 | 100 | 257 | 48 | 37 | 21 | 33 | 14 | 4/4 OK | `deterministic_engine` | **PASSED** | 36.5s |
| `inversify/InversifyJS` | TypeScript | 11,400 | YES | `583d30ab..fdd91868` | 100 | 100 | 22 | 16 | 6 | 0 | 0 | 0 | 4/4 OK | `deterministic_engine` | **PASSED** | 6.97s |
| `marshmallow-code/marshmallow` | Python | 10,100 | YES | `5d3b1ccc..b762ea2d` | 147 | 100 | 293 | 40 | 17 | 3 | 8 | 4 | 4/4 OK | `deterministic_engine` | **PASSED** | 20.48s |
| `simdjson/simdjson` | C++ | 19,500 | YES | `edd9760b..fc358c5c` | 100 | 100 | 231 | 206 | 134 | 17 | 119 | 27 | 4/4 OK | `deterministic_engine` | **PASSED** | 53.54s |

## 3. Ground-Truth Semantic Quality Benchmark (19 Scenarios — 100% Pass Rate)

In addition to live public repository crawls, Athena was validated against a ground-truth suite of 19 API & recursion mutation scenarios:

| Benchmark Scenario | Ground Truth Contract Change | Athena Detection Result | Confidence | Evidence Grounding |
| :--- | :--- | :--- | :--- | :--- |
| **Renamed Public Function** | Symbol removed; replacement introduced | Flagged as removed public symbol requiring review | High | Exact file & line span |
| **Added Required Parameter** | Added `idempotency_key` without default | Flagged as breaking signature mutation | High | Exact file, line & diff hunk |
| **Guarded `default=None`** | Default changed to `None` with body guard | Exempted as non-breaking (`griffe#469` pattern) | High | Body AST verification |
| **Unguarded `default=None`** | Default changed to `None` without guard | Flagged as breaking (`TypeError` risk) | High | AST body inspection |
| **Return Type Annotation** | Return annotation changed `bool` -> `dict` | Flagged as return type mutation | Medium | Exact AST diff |
| **Newly Raised Exception** | Function now raises `ValueError` | Flagged as newly raised exception path | High | Exception raise AST trace |
| **Base Class Mutation** | Enum base changed `(str, Enum)` -> `(Enum)` | Flagged as potential inheritance break | High | Class definition diff |
| **Harmless Internal Refactor** | Variable rename / whitespace cleanup | Correctly omitted from breaking changes | High | 0 false positives |
| **Downstream Caller Blast Radius** | External caller invokes modified function | Mapped to `src/orders.py:6` (`exact_ast`) | High | Import graph grounded |
| **Documentation Drift** | README code snippets reference old API | Detected stale calls in `README.md:4` & `:5` | High | Line & symbol matched |
| **Empty / Non-Source Range** | Identical revisions or doc-only changes | Empty diff handled gracefully without crash | High | Zero hallucinations |
| **Large Diff & Lockfiles** | 180+ lines in lockfiles (`poetry.lock`) | Excluded from AST token budgets | High | File filter verified |
| **Public API Export Boundary** | `__all__` / `__init__.py` re-export vs `_internal.py` | Public exports vs private helpers distinguished | High | Export trace verified |
| **Unresolved Dynamic Calls** | `getattr`, `importlib`, `globals()` dispatch | Flagged & blast-radius confidence adjusted | High | AST call inspection |
| **`(str, Enum)` -> `StrEnum`** | Python 3.11+ `StrEnum` format change (`griffe#501`) | Flagged as breaking inheritance change | High | Base tuple comparison |
| **Adversarial `.gitconfig` & Drift** | `diff.noprefix=true` + stale Markdown arity | Immune to gitconfig; stale call arity caught | High | `--no-ext-diff` + parser |
| **Recursive Function Arity Break** | Recursive function adds required param, omits in self-call | Flagged in breaking findings & `affected_callers` | High | Self-call AST arity check |
| **Infinite Recursion & Method Call** | Missing base case & unqualified `step()` in class method | Flagged `RecursionError` & `NameError` defects | High | AST control-flow guard check |
| **Ollama `gemma:latest` (Gemma 7B)** | Hybrid recursive diff synthesis with `gemma:7b` alias | `ollama:gemma:latest` verified with 0 hallucinations | High | Verified against `ev_001` |