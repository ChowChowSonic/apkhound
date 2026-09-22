<p align="center">
  <img src="assets/apkhound.png" alt="apkhound" width="600">
</p>

<h1 align="center">apkhound</h1>

<p align="center">
  <a href="https://github.com/ChowChowSonic/apkhound/actions/workflows/ci.yml"><img src="https://github.com/ChowChowSonic/apkhound/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/rust-stable-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
</p>

<p align="center">
  <strong>A static analysis toolkit for comparing Android APK files.</strong>
  <br>
  DEX bytecode inspection, method-level diffing, call graphs, and Weisfeiler-Lehman graph kernel package matching.
</p>

---

## Features

- **Call graph extraction** — Generate a Graphviz DOT digraph of method invocations across all DEX files in an APK.
- **Call path tracing** — Find the shortest invocation paths between methods matching a source regex and methods matching a destination regex, e.g. from UI entry points to sensitive sinks.
- **APK diffing** — Compare two APK versions at the method-signature level and list added, removed, and changed methods.
- **Smali extraction** — Dump the smali source of changed/added/removed methods to disk for manual review.
- **Graph kernel matching** — Match packages across APK versions using a Weisfeiler-Lehman (WL) graph kernel blended with API-call fingerprint similarity, string-constant content fingerprints, hierarchical ancestor-consistency refinement, and empty-package matching with default-package collapse awareness. Configurable similarity thresholds and weighting controls.
- **Permission diffing** — List or diff `uses-permission` entries between APK versions.
- **Manifest inspection** — Extract and display `AndroidManifest.xml` in human-readable, JSON, YAML, or raw XML format.
- **Statistics** — Report structural metrics (classes, methods, instructions, opcode families, call-graph shape) for one or more APKs, including a two-APK metric diff.

## Installation

```bash
git clone https://github.com/ChowChowSonic/apkhound.git
cd apkhound
cargo build --release
```

The binary is placed at `target/release/apkhound`.

## Quick Start

```bash
# Compare two APK versions
apkhound compare app-v1.0.apk app-v1.1.apk

# Run the WL graph kernel matcher
apkhound match app-v1.0.apk app-v1.1.apk --show-details

# Extract a filtered call graph
apkhound callgraph app.apk -f "com.example" > graph.dot

# Trace call paths from entry points to a sensitive sink
apkhound trace "onCreate" "sendTextMessage|loadUrl" app.apk

# Display the manifest
apkhound manifest app.apk json

# Report statistics for an APK (including call-graph metrics)
apkhound stats app.apk --graph

# Diff statistics between two APK versions
apkhound stats app-v1.0.apk app-v1.1.apk
```

## CLI Reference

### `callgraph`

Extract a call graph from one or more APK files as a Graphviz DOT digraph.

```
apkhound callgraph <apk_path>... [-f <regex>...]
```

| Flag | Description |
|------|-------------|
| `-f`, `--filterclass` | Regex filter for class/method names (repeatable) |

### `compare`

List methods that were added, removed, or changed between two APK versions.

```
apkhound compare <old_apk> <new_apk> [-f <regex>...]
```

| Flag | Description |
|------|-------------|
| `-f`, `--filterclass` | Regex filter for class names (repeatable) |

Output prefixes: `ADDED:`, `REMOVED:`, `CHANGED:`.

### `extract`

Dump smali source of changed methods to disk.

```
apkhound extract <old_apk> <new_apk> <output_dir> [-f <class_regex>...] [-s <smali_regex>...]
```

| Flag | Description |
|------|-------------|
| `-f`, `--filterclass` | Regex filter for class names (repeatable) |
| `-s`, `--filtersmali` | Regex filter for smali line content (repeatable) |

Output: `<output_dir>/old/` and `<output_dir>/new/` mirroring the original directory structure. This output is best viewed with a tool like [ripdiff](https://github.com/ChowChowSonic/ripdiff) to more easily get a sense of what changed.

### `trace`

Find call paths from methods matching a source regex to methods matching a destination regex.

```
apkhound trace <src_regex> <dest_regex> <apk_path>... [-S <src_file>] [-D <dest_file>] [-f <format>]
```

| Flag | Description |
|------|-------------|
| `-S`, `--src-from-file` | Treat `<src_regex>` as a path to a file whose non-empty lines are source regexes |
| `-D`, `--dest-from-file` | Treat `<dest_regex>` as a path to a file whose non-empty lines are destination regexes |
| `-f`, `--format` | Output format: `printed` (default), `json`, `yaml`, `xml`, `csv` |

```
apkhound trace -S src_patterns.txt "loadUrl|sendTextMessage" app.apk
apkhound trace -S -D src_patterns.txt dest_patterns.txt app.apk
```

A file's non-empty lines are each treated as a separate regex (blank lines and
line endings are ignored), so the file offers a convenient place to list
patterns that get unwieldy on the command line.

Signatures are formatted as `class:method`, e.g. `com.example.MainActivity:onCreate`. Both regexes are matched with an unanchored search (`is_match`), so `"onCreate"` matches any `onCreate` method while `"^com\.example\.MainActivity:onCreate$"` pins the exact signature. Destinations may match any method mentioned in the graph — including framework methods that only appear as callees, such as `SmsManager:sendTextMessage` — not just methods declared in the APK.

For every matching source, a single breadth-first search over the APK's call graph finds the shortest path to every reachable destination. Only paths that actually exist are printed:

```
com.example.MainActivity:onCreate -> android.telephony.SmsManager:sendTextMessage
"com.example.MainActivity:onCreate"
"com.example.internal.SmsHelper:send"
"android.telephony.SmsManager:sendTextMessage"
```

When no paths are found the command prints a warning to stderr and exits successfully; nothing is printed to stdout.

### `match`

Run the Weisfeiler-Lehman graph kernel matcher to find corresponding packages between two APK versions.

```
apkhound match <old_apk> <new_apk> [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--threshold` | `0.8` | Similarity score to consider packages a match |
| `--change-threshold` | `0.0` | Minimum similarity to consider packages related |
| `--wl-iterations` | `3` | Number of WL label-refinement iterations |
| `--api-weight` | `0.2` | Weight of API-call fingerprint similarity in the combined score (0 = pure WL, 1 = pure API) |
| `--string-weight` | `0.3` | Weight of string-constant content fingerprint similarity (added to base score; 0 = disabled) |
| `--hier-weight` | `0.7` | Weight of hierarchical ancestor-consistency boost applied after flat matching |
| `--csv` | `false` | Output as CSV instead of a formatted table |
| `-d`, `--show-details` | `false` | Show per-package method counts |
| `--node-matching` | `false` | Enable node-label consistency check for more precise matching |
| `-f`, `--filterclass` | — | Regex filter for class names (repeatable) |

Each matched pair is classified as `MATCH`, `CHANGED`, `REMOVED`, or `NEW` based on the thresholds.

### `permissions`

List permissions from one APK, or diff permissions between two.

```
apkhound permissions <apk_path> [<apk_path>]
```

With one argument: lists all declared permissions. With two: shows added and removed permissions.

### `manifest`

Display `AndroidManifest.xml` in a choice of formats.

```
apkhound manifest <apk_path> [format]
```

| Format | Description |
|--------|-------------|
| `printed` (default) | Human-readable text report |
| `json` | Pretty-printed JSON |
| `yaml` | YAML |
| `xml` | Raw XML |

### `stats`

Report structural statistics for one or two APKs; when two are given, also
emit a metric diff between them. The command rejects any other number of
APK paths.

```
apkhound stats <apk_path> [<apk_path>] [-f <regex>...] [-g] [--format printed|json|csv]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-f`, `--filterclass` | — | Regex filter for class names (repeatable) |
| `-g`, `--graph` | `false` | Also compute call-graph metrics (requires an extra parse pass) |
| `--format` | `printed` | Output format: `printed`, `json`, or `csv` |

Reported metrics:

- **APK-level** — file size in bytes, number of DEX entries
- **Code** — classes, methods, constructors, instructions (total / avg / min / max per method), methods per modifier (public, private, static, …), and opcode-family counts: `invoke-*` kinds, `const-*`, string constants, field access, branches, returns, moves, monitors, allocations, exceptions, array access, comparisons, and try/catch. The top 10 packages by class count are listed too.
- **Call graph** (with `--graph`) — nodes, edges, max in/out degree, isolated methods, and density

All numbers respect the `-f` class filters. With two APKs, the `printed` and
`json` outputs also include:

- a `Diff (old -> new)` section showing the delta and percent change for every metric, and
- a **Change coverage (old -> new)** section that measures how much of the code actually changed, broken down by classes, methods, and instructions. For each unit type it reports how many were `added` (only in the new APK), `removed` (only in the old APK), `modified` (present in both but with different bytecode — method bodies are compared opcode-for-opcode, exactly like `compare`), and `unchanged`. `union` is the number of distinct units across both APKs and `%changed` is `(added + removed + modified) / union`, so it is always between 0 and 100%. For example, "methods: 65.02%" means 65% of all distinct methods that exist in either version differ between the two.

`csv` emits one row per APK.

```
apkhound stats app.apk
apkhound stats app.apk --graph --format json
apkhound stats app-v1.0.apk app-v1.1.apk
```

## How It Works

### DEX Parsing

APK files are parsed using the [`smali`](https://crates.io/crates/smali) crate, which handles ZIP extraction, DEX bytecode decoding, and binary XML parsing. Each DEX entry is decompiled into structured `SmaliClass` and `SmaliMethod` types.

### Call Graph Construction

For every method in every DEX file, every `invoke-*` opcode is extracted to build a `HashMap<caller_signature, Vec<callee_signature>>`. The result is emitted as a Graphviz DOT digraph.

### Call Path Tracing

The `trace` command searches the call graph for invocation paths from methods matching a source regex to methods matching a destination regex. Sources must be graph keys (methods that make calls), while destinations can be any method mentioned in the graph — including callee-only nodes such as framework sinks. A single BFS per source records parent pointers, so the shortest path to every reachable destination is reconstructed from one traversal instead of one traversal per pair.

### Method-Level Diffing

Methods are identified by their full Java signature (class name + method name + parameter types). Between two APK versions, the tool classifies each method as:
- **Added** — present in the new APK but not the old
- **Removed** — present in the old APK but not the new
- **Changed** — same signature but differing bytecode

### Weisfeiler-Lehman Graph Kernel Matching

Packages from two APK versions are matched using a multi-component similarity pipeline:

1. **Feature extraction**: Each method is represented by a 19-dimensional feature vector:
   `[in_degree, out_degree, ext_android, ext_java, ext_kotlin, ext_other, invoke_virtual, invoke_static, invoke_direct, invoke_interface, num_params, num_instructions, has_branches, string_consts, field_access, try_catch, register_count, is_constructor, return_type]`
   String-constant *values* are also collected into a per-package set for content fingerprinting.

2. **Graph construction**: Methods within a package become nodes; intra-package call edges connect them.

3. **WL refinement**: Each node's label is iteratively combined with its neighbors' labels and hashed, producing a multi-level histogram signature for each package.

4. **WL similarity scoring**: Histogram intersection across all WL iterations yields a score: `min(cross) / sqrt(self_a × self_b)`.

5. **API fingerprint similarity**: Each package records the set of external API calls it makes (class + method name pairs). Since framework and library classes are never renamed by obfuscators, these fingerprints survive renaming. The similarity between two packages is computed as Jaccard similarity over their API-call sets.

6. **String-constant content fingerprint**: Each package collects the literal string values referenced in its methods (e.g., URLs, log tags, error messages). Since R8 keeps string content intact during obfuscation, these serve as a stable signal. Similarity is Jaccard over the two packages' string sets, weighted by `--string-weight`.

7. **Combined scoring**: The final score blends WL, API, and string similarity, then optionally boosts via hierarchical consistency:
   ```
   base_score = (1 - api_weight) * s_wl + api_weight * s_api
   base_score += string_weight * s_string
   final_score = min(base_score * (1.0 + hier_weight * hier_consistency), 1.0)
   ```
   Where `hier_consistency` measures agreement between the matched pair's ancestor package chains.

8. **Two-pass bipartite matching**:
   - **Pass 1**: Old packages are greedily matched to new packages by best base score.
   - **Hierarchy boost**: Pass-1 results are used to compute ancestor-consistency scores for every candidate pair.
   - **Pass 2**: Matching is re-run with the boosted final scores, improving same-package-name and sibling-package matches.

9. **Node-label consistency** (optional): After histogram matching, re-scores each pair by comparing per-node `(label, sorted_neighbor_labels)` tuples for more precise matching.

10. **Default-package collapse handling**: R8's obfuscation often flattens the majority of classes into the unnamed `(default)` package, which would otherwise cause false many-to-one matches. When the `(default)` package is a candidate, the bijective greedy assignment is relaxed, allowing multiple old packages to find their best new match there.

11. **Empty-package matching**: Packages without graph content (no methods or no call edges) are matched by same package name against both empty and non-empty candidates. Unmatched packages are flagged as `REMOVED` or `NEW`.

12. **Classification**: Each matched pair is classified as `MATCH` (score ≥ threshold), `CHANGED` (score > change-threshold), `REMOVED` (old package with no new match), or `NEW` (new package with no old match).

## Project Structure

```
├── Cargo.toml
├── assets/
│   └── apkhound.svg
├── benches/
│   └── speed_test.rs           # Criterion benchmarks
├── src/
│   ├── main.rs                 # CLI entry point (clap)
│   ├── lib.rs                  # Library root
│   ├── callgraph.rs            # DEX call-graph extraction
│   ├── compare.rs              # APK diff and smali dump
│   ├── matching.rs             # WL graph kernel matching
│   ├── manifest_summary.rs     # Manifest parse + JSON/YAML output
│   ├── stats.rs                # APK statistics and diffs
│   ├── utils.rs                # Shared helpers, permission diffing
│   └── commands/
│       ├── mod.rs
│       ├── callgraph.rs
│       ├── compare.rs
│       ├── extract.rs
│       ├── manifest.rs
│       ├── match_cmd.rs
│       ├── permissions.rs
│       ├── stats.rs
│       └── trace.rs
└── tests/
    └── integration_test.rs     # 20 binary-level integration tests
```

## Testing & Benchmarks

```bash
# Unit tests (126 tests across lib modules)
cargo test --lib

# Integration tests (requires VLC APKs — downloaded in CI)
cargo test --test integration_test

# Benchmarks (4 criterion benchmarks)
cargo bench
```

CI runs on every push and pull request via GitHub Actions: format check, clippy lint, unit tests, integration tests (with APK download), and a release build with artifact upload.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| [`clap`](https://crates.io/crates/clap) | 4.6.1 | CLI argument parsing |
| [`rayon`](https://crates.io/crates/rayon) | 1.12.0 | Data parallelism |
| [`regex`](https://crates.io/crates/regex) | 1.13.0 | Method/class/smali filtering |
| [`smali`](https://crates.io/crates/smali) | 0.5.2 | APK/DEX/smali parsing |
| [`serde`](https://crates.io/crates/serde) / `serde_json` / `serde_yaml` | — | Serialization for manifest output |
| [`rustc-hash`](https://crates.io/crates/rustc-hash) | 2.1 | Fast hashing (`FxHashMap`) |
| [`roxmltree`](https://crates.io/crates/roxmltree) | 0.21.1 | XML parsing |
| [`tracing`](https://crates.io/crates/tracing) / `tracing-subscriber` | — | Structured logging |

## License

MIT © 2026 Joseph Antonucci

See [LICENSE](LICENSE) for the full text.
