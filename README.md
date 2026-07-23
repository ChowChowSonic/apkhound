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
- **APK diffing** — Compare two APK versions at the method-signature level and list added, removed, and changed methods.
- **Smali extraction** — Dump the smali source of changed/added/removed methods to disk for manual review.
- **Graph kernel matching** — Match packages across APK versions using a Weisfeiler-Lehman (WL) graph kernel with configurable similarity thresholds and optional node-label consistency checking.
- **Permission diffing** — List or diff `uses-permission` entries between APK versions.
- **Manifest inspection** — Extract and display `AndroidManifest.xml` in human-readable, JSON, YAML, or raw XML format.

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

# Display the manifest
apkhound manifest app.apk json
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

## How It Works

### DEX Parsing

APK files are parsed using the [`smali`](https://crates.io/crates/smali) crate, which handles ZIP extraction, DEX bytecode decoding, and binary XML parsing. Each DEX entry is decompiled into structured `SmaliClass` and `SmaliMethod` types.

### Call Graph Construction

For every method in every DEX file, every `invoke-*` opcode is extracted to build a `HashMap<caller_signature, Vec<callee_signature>>`. The result is emitted as a Graphviz DOT digraph.

### Method-Level Diffing

Methods are identified by their full Java signature (class name + method name + parameter types). Between two APK versions, the tool classifies each method as:
- **Added** — present in the new APK but not the old
- **Removed** — present in the old APK but not the new
- **Changed** — same signature but differing bytecode

### Weisfeiler-Lehman Graph Kernel Matching

The core innovation — packages from two APK versions are matched using graph isomorphism via the WL kernel:

1. **Feature extraction**: Each method is represented by a 13-dimensional feature vector:
   `[in_degree, out_degree, ext_android, ext_java, ext_kotlin, ext_other, invoke_virtual, invoke_static, invoke_direct, invoke_interface, num_params, num_instructions, has_branches]`

2. **Graph construction**: Methods within a package become nodes; intra-package call edges connect them.

3. **WL refinement**: Each node's label is iteratively combined with its neighbors' labels and hashed, producing a multi-level histogram signature for each package.

4. **Similarity scoring**: Histogram intersection across all WL iterations yields a score: `min(cross) / sqrt(self_a × self_b)`.

5. **Bipartite matching**: Old packages are greedily matched to new packages by best similarity score.

6. **Node-label consistency** (optional): After histogram matching, re-scores each pair by comparing per-node `(label, sorted_neighbor_labels)` tuples for more precise matching.

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
│   ├── utils.rs                # Shared helpers, permission diffing
│   └── commands/
│       ├── mod.rs
│       ├── callgraph.rs
│       ├── compare.rs
│       ├── extract.rs
│       ├── manifest.rs
│       ├── match_cmd.rs
│       └── permissions.rs
└── tests/
    └── integration_test.rs     # 10 binary-level integration tests
```

## Testing & Benchmarks

```bash
# Unit tests (41 tests across lib modules)
cargo test --lib

# Integration tests (requires VLC APKs — downloaded in CI)
cargo test --test integration_test

# Benchmarks (3 criterion benchmarks)
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
