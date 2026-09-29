//! Implementation of the `trace` command: find call paths between methods
//! matching a source regex and methods matching a destination regex.
//!
//! The call graph is built by [`crate::callgraph::iterate_over_dex_files`]
//! and represented as a map from caller signature (`class:method`) to the
//! list of callee signatures it invokes. A single breadth-first search per
//! source records parent pointers, so the shortest path to every reachable
//! destination is reconstructed from one traversal. Destinations may be any
//! method mentioned in the graph (including framework methods that only
//! appear as callees), not just methods declared in the APK.

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use rustc_hash::{FxHashMap, FxHashSet};
use smali::android::zip::ApkFile;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use crate::callgraph::iterate_over_dex_files;
use crate::commands::manifest::Format;

/// Walk the `parents` map backwards from `end` to the source (the only node
/// without a parent entry), then return the path in source-to-end order.
fn reconstruct_path(parents: &FxHashMap<String, String>, end: &str) -> Vec<String> {
    let mut path = vec![end.to_string()];
    let mut current = end.to_string();

    while let Some(parent) = parents.get(&current) {
        path.push(parent.to_string());
        current = parent.clone();
    }
    path.reverse();
    path
}

/// Run a single BFS from `start`, recording the shortest path to every
/// destination in `dests`.  Only destinations that are actually reached
/// produce a result.  `dests` may contain nodes that are not keys of `map`
/// (e.g. framework methods that only appear as callees); those still work,
/// since the BFS terminates when a popped node matches a destination.
fn bfs_to_all(
    map: &FxHashMap<String, Vec<String>>,
    start: &str,
    dests: &FxHashSet<String>,
) -> Vec<Vec<String>> {
    let mut parents: FxHashMap<String, String> = FxHashMap::default();
    let mut visited: FxHashSet<String> = FxHashSet::default();
    let mut q: VecDeque<String> = VecDeque::new();
    let mut found: Vec<Vec<String>> = Vec::new();
    visited.insert(start.to_string());
    q.push_back(start.to_string());
    while let Some(top) = q.pop_front() {
        if dests.contains(&top) {
            found.push(reconstruct_path(&parents, &top));
        }
        if let Some(neighbors) = map.get(&top) {
            for neighbor in neighbors.iter() {
                if visited.insert(neighbor.clone()) {
                    parents.insert(neighbor.clone(), top.clone());
                    q.push_back(neighbor.clone());
                }
            }
        }
    }
    found
}

/// Find the shortest path from every method matching any regex in `starts`
/// to every method matching any regex in `dests` (which may be a graph key
/// or a callee-only node).  Each node is checked against the regexes in
/// parallel.  Runs one BFS per start, in parallel.
fn multi_to_multi_bfs(
    map: &FxHashMap<String, Vec<String>>,
    starts: &[Regex],
    dests: &[Regex],
) -> Vec<Vec<String>> {
    let starts: Vec<String> = map
        .par_iter()
        .filter(|(k, _v)| starts.par_iter().any(|re| re.is_match(k)))
        .map(|(k, _v)| k.clone())
        .collect();
    let dests: FxHashSet<String> = map
        .par_iter()
        .flat_map_iter(|(k, v)| std::iter::once(k.clone()).chain(v.iter().cloned()))
        .filter(|n| dests.par_iter().any(|re| re.is_match(n)))
        .collect();
    starts
        .par_iter()
        .flat_map_iter(|start| bfs_to_all(map, start, &dests))
        .collect()
}

/// Render found paths in the same format `handle_trace` prints: a
/// `first -> last` header, one quoted signature per path node, and a blank
/// line after each path.
fn format_paths(results: &[Vec<String>], format: Format) -> String {
    let mut out = String::new();
    match format {
        Format::Printed => {
            for res in results {
                let first = res.first().map_or("<unknown>", |x| x);
                let last = res.last().map_or("<unknown>", |x| x);
                out.push_str(&format!("{} -> {}\n", first, last));
                for path_item in res {
                    out.push_str(&format!("{:?}\n", path_item));
                }
                out.push('\n');
            }
            out
        }
        Format::Json => {
            let json_res = serde_json::ser::to_string(results);
            match json_res {
                Ok(json) => {
                    out.push_str(&json);
                }
                Err(j) => {
                    tracing::error!("Unable to serialize results into json: {:?}", j);
                }
            }
            out
        }
        Format::Yaml => {
            let yaml_res = serde_yaml::to_string(results);
            match yaml_res {
                Ok(yaml) => {
                    out.push_str(&yaml);
                }
                Err(e) => {
                    tracing::error!("Unable to serialize results into YAML: {:?}", e);
                }
            }
            out
        }
        Format::Xml => {
            out.push_str("<?xml version=\"1.0\"?><root>\n");
            for res in results {
                out.push_str("<path>\n");
                for path_item in res {
                    out.push_str("<pathItem>\n");
                    out.push_str(path_item);
                    out.push_str("\n</pathItem>\n");
                }
                out.push_str("</path>\n");
            }
            out.push_str("</root>\n");
            out
        }
        Format::CSV => {
            out.push_str("start,call 1, call 2, ...,\n");
            for res in results {
                let mut line = String::new();
                for path_item in res {
                    line.push_str(path_item);
                    line.push(',');
                }
                out.push_str(&line);
                out.push('\n');
            }
            out
        }
    }
}

/// Resolve the regexes for one side of a trace.  When `from_file` is false,
/// the positional pattern is kept as-is.  When true, the positional pattern
/// is itself the path to a file whose each non-empty trimmed line (with
/// trailing carriage returns stripped) becomes one pattern, preserving the
/// ability to check them in parallel later.  An unreadable or empty file is
/// an error.
fn resolve_patterns(pattern: &str, from_file: bool) -> Result<Vec<String>, String> {
    if !from_file {
        return Ok(vec![pattern.to_string()]);
    }
    let path = Path::new(pattern);
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let patterns: Vec<String> = content
        .replace('\r', "")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if patterns.is_empty() {
        Err(format!("{} contains no non-empty regexes", path.display()))
    } else {
        Ok(patterns)
    }
}

/// Compile every resolved pattern into a `Regex`.  An invalid pattern is a
/// hard error: the process reports it and aborts, matching the previous
/// behavior of a single positional regex.
fn compile_patterns(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .map(|p| {
            Regex::new(p).unwrap_or_else(|e| {
                tracing::error!("Error parsing regex {}: {}", p, e);
                panic!("Failed to parse regex");
            })
        })
        .collect()
}

/// Find call paths from methods matching any of the `start` regexes to
/// methods matching any of the `end` regexes across all given APKs, and
/// print the results to stdout.  Signatures are formatted as `class:method`,
/// e.g. `com.example.MainActivity:onCreate`.  When a `*_from_file` flag is
/// set the corresponding positional arg is treated as a path to a file whose
/// non-empty lines are patterns. Returns an error only when a regex file is
/// unreadable or empty, or no APK can be read; a missing APK is silently
/// skipped, and a search that finds nothing prints a warning to stderr and
/// succeeds.
pub fn handle_trace(
    start_regex: String,
    end_regex: String,
    src_from_file: bool,
    dest_from_file: bool,
    format: Format,
    apks: Vec<PathBuf>,
    match_obfuscated: bool,
) -> Result<(), String> {
    let start_patterns = resolve_patterns(&start_regex, src_from_file)?;
    let end_patterns = resolve_patterns(&end_regex, dest_from_file)?;
    let files: Vec<ApkFile> = apks
        .par_iter()
        .filter_map(|x| ApkFile::from_file(x).ok())
        .collect::<Vec<ApkFile>>();

    let (start_regs, end_regs) = if match_obfuscated && files.len() >= 2 {
        let match_params = crate::matching::MatchParams::default();
        let old_classes = crate::compare::unpack_apk_classes(&files[0], &[]);
        let new_classes = crate::compare::unpack_apk_classes(&files[1], &[]);
        let match_set =
            crate::matching::build_class_match_set(&old_classes, &new_classes, &match_params);

        let mut extended_start_patterns = start_patterns.clone();
        let mut extended_end_patterns = end_patterns.clone();

        for m in &match_set.matches {
            for p in &start_patterns {
                if p.contains(&m.old_class) {
                    extended_start_patterns.push(p.replace(&m.old_class, &m.new_class));
                }
            }
            for p in &end_patterns {
                if p.contains(&m.old_class) {
                    extended_end_patterns.push(p.replace(&m.old_class, &m.new_class));
                }
            }
        }
        extended_start_patterns.sort();
        extended_start_patterns.dedup();
        extended_end_patterns.sort();
        extended_end_patterns.dedup();

        (
            compile_patterns(&extended_start_patterns),
            compile_patterns(&extended_end_patterns),
        )
    } else {
        if match_obfuscated && files.len() < 2 {
            tracing::info!(
                "--match-obfuscated specified with fewer than 2 APKs; skipping matching analysis"
            );
        }
        (
            compile_patterns(&start_patterns),
            compile_patterns(&end_patterns),
        )
    };

    let start_maps: Vec<FxHashMap<String, Vec<String>>> = files
        .par_iter()
        .map(|x| iterate_over_dex_files(x, &[]))
        .collect();
    let results: Vec<Vec<String>> = start_maps
        .par_iter()
        .fold(Vec::<Vec<String>>::new, |mut cumulator, x| {
            let t = multi_to_multi_bfs(x, &start_regs, &end_regs);
            cumulator.extend(t);
            cumulator
        })
        .reduce(Vec::new, |mut accumulator, mut other| {
            accumulator.append(&mut other);
            accumulator
        });
    if results.is_empty() {
        let start = start_patterns.join("|");
        let end = end_patterns.join("|");
        tracing::warn!("No paths found from {start} to {end}");
        return Ok(());
    }
    print!("{}", format_paths(&results, format));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(pairs: &[(&str, &[&str])]) -> FxHashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    fn dests(names: &[&str]) -> FxHashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_bfs_simple_path() {
        let g = graph(&[("A", &["B", "C"]), ("B", &["D"]), ("C", &["D"]), ("D", &[])]);
        assert_eq!(
            bfs_to_all(&g, "A", &dests(&["D"])),
            vec![vec!["A", "B", "D"]]
        );
    }

    #[test]
    fn test_bfs_shortest_path() {
        let g = graph(&[("A", &["B", "C"]), ("B", &["D"]), ("C", &["D"]), ("D", &[])]);
        // B and C are both one hop from A; D is reachable via B or C.
        assert_eq!(
            bfs_to_all(&g, "A", &dests(&["D"])),
            vec![vec!["A", "B", "D"]]
        );
    }

    #[test]
    fn test_bfs_cycle_terminates() {
        let g = graph(&[
            ("A", &["B"]),
            ("B", &["A", "C"]),
            ("C", &["C", "D"]),
            ("D", &["B"]),
        ]);
        assert_eq!(
            bfs_to_all(&g, "A", &dests(&["D"])),
            vec![vec!["A", "B", "C", "D"]]
        );
    }

    #[test]
    fn test_bfs_no_path() {
        let g = graph(&[("A", &["B"]), ("B", &[]), ("C", &["D"]), ("D", &[])]);
        assert!(bfs_to_all(&g, "A", &dests(&["D"])).is_empty());
    }

    #[test]
    fn test_bfs_start_equals_end() {
        let g = graph(&[("A", &["B"]), ("B", &["A"])]);
        assert_eq!(bfs_to_all(&g, "A", &dests(&["A"])), vec![vec!["A"]]);
    }

    #[test]
    fn test_bfs_multiple_dests() {
        let g = graph(&[
            ("A", &["B", "C"]),
            ("B", &["D"]),
            ("C", &["E"]),
            ("D", &[]),
            ("E", &[]),
        ]);
        assert_eq!(
            bfs_to_all(&g, "A", &dests(&["D", "E"])),
            vec![vec!["A", "B", "D"], vec!["A", "C", "E"]]
        );
    }

    #[test]
    fn test_multi_to_multi_bfs_framework_dest() {
        // The destination only appears as a callee, never as a key of the
        // map -- like a framework method in a real APK. It must still be
        // found as a valid end point.
        let g = graph(&[
            ("com.a.Source:x", &["com.b.Mid:y"]),
            ("com.b.Mid:y", &["com.c.Sink:z"]),
        ]);
        let starts = Regex::new("Source").unwrap();
        let dests = Regex::new("Sink").unwrap();
        let paths = multi_to_multi_bfs(&g, &[starts], &[dests]);
        assert_eq!(
            paths,
            vec![vec!["com.a.Source:x", "com.b.Mid:y", "com.c.Sink:z"]]
        );
    }

    #[test]
    fn test_multi_to_multi_bfs_unreachable() {
        let g = graph(&[("com.a.Source:x", &["com.b.Mid:y"])]);
        let starts = Regex::new("Source").unwrap();
        let dests = Regex::new("Sink").unwrap();
        assert!(multi_to_multi_bfs(&g, &[starts], &[dests]).is_empty());
    }

    #[test]
    fn test_multi_to_multi_bfs_mixed_reachability() {
        let g = graph(&[
            ("com.a.Source:x", &["com.b.Mid:y"]),
            ("com.b.Mid:y", &["com.c.Sink:z"]),
            ("com.z.Other:leaf", &[]),
        ]);
        let starts = Regex::new("Source").unwrap();
        let dests = Regex::new("Sink|Other").unwrap();
        let paths = multi_to_multi_bfs(&g, &[starts], &[dests]);
        assert_eq!(
            paths,
            vec![vec!["com.a.Source:x", "com.b.Mid:y", "com.c.Sink:z"]]
        );
    }

    #[test]
    fn test_multi_to_multi_bfs_dedup_dests() {
        // A node that is both a key and a callee must not be matched twice.
        let g = graph(&[
            ("com.a.Source:x", &["com.b.Mid:y"]),
            ("com.b.Mid:y", &["com.c.Sink:z"]),
            ("com.c.Sink:z", &["com.d.Other:q"]),
        ]);
        let starts = Regex::new("Source").unwrap();
        let dests = Regex::new("Sink|Other").unwrap();
        let paths = multi_to_multi_bfs(&g, &[starts], &[dests]);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec![
            "com.a.Source:x".to_string(),
            "com.b.Mid:y".to_string(),
            "com.c.Sink:z".to_string(),
        ]));
        assert!(paths.contains(&vec![
            "com.a.Source:x".to_string(),
            "com.b.Mid:y".to_string(),
            "com.c.Sink:z".to_string(),
            "com.d.Other:q".to_string(),
        ]));
    }

    #[test]
    fn test_reconstruct_path_walks_to_start() {
        let mut parents: FxHashMap<String, String> = FxHashMap::default();
        parents.insert("B".to_string(), "A".to_string());
        parents.insert("C".to_string(), "B".to_string());
        assert_eq!(reconstruct_path(&parents, "C"), vec!["A", "B", "C"]);
    }

    #[test]
    fn test_reconstruct_path_no_parents() {
        assert_eq!(reconstruct_path(&FxHashMap::default(), "A"), vec!["A"]);
    }

    #[test]
    fn test_bfs_start_not_in_map() {
        // Start is not a key; no expansion is possible.
        let g = graph(&[("B", &["D"]), ("D", &[])]);
        assert!(bfs_to_all(&g, "A", &dests(&["D"])).is_empty());
    }

    #[test]
    fn test_bfs_empty_dests() {
        let g = graph(&[("A", &["B"]), ("B", &[])]);
        assert!(bfs_to_all(&g, "A", &dests(&[])).is_empty());
    }

    #[test]
    fn test_bfs_self_loop() {
        let g = graph(&[("A", &["A", "B"]), ("B", &[])]);
        assert_eq!(bfs_to_all(&g, "A", &dests(&["B"])), vec![vec!["A", "B"]]);
    }

    #[test]
    fn test_bfs_direct_edge_wins_over_longer_path() {
        // A direct A -> B edge competes with the longer A -> C -> D -> B
        // route; BFS must return the shortest path.
        let g = graph(&[("A", &["B", "C"]), ("B", &[]), ("C", &["D"]), ("D", &["B"])]);
        assert_eq!(bfs_to_all(&g, "A", &dests(&["B"])), vec![vec!["A", "B"]]);
    }

    #[test]
    fn test_bfs_unreachable_dests_omitted() {
        // Only reached destinations produce results.
        let g = graph(&[("A", &["B"]), ("B", &["C"]), ("C", &[])]);
        assert_eq!(
            bfs_to_all(&g, "A", &dests(&["C", "Z"])),
            vec![vec!["A", "B", "C"]]
        );
    }

    #[test]
    fn test_bfs_framework_dest() {
        // The destination is a callee-only node (never a key), like a
        // framework method in a real APK.
        let g = graph(&[("A", &["B"]), ("B", &["C"])]);
        assert_eq!(
            bfs_to_all(&g, "A", &dests(&["C"])),
            vec![vec!["A", "B", "C"]]
        );
    }

    #[test]
    fn test_multi_to_multi_bfs_no_starts_match() {
        let g = graph(&[("com.a.Other:x", &["com.b.Mid:y"])]);
        let starts = Regex::new("Source").unwrap();
        let dests = Regex::new("Mid").unwrap();
        assert!(multi_to_multi_bfs(&g, &[starts], &[dests]).is_empty());
    }

    #[test]
    fn test_multi_to_multi_bfs_multiple_starts() {
        let g = graph(&[
            ("com.a.Source1:x", &["com.b.Mid:y"]),
            ("com.a.Source2:z", &["com.b.Mid:y"]),
            ("com.b.Mid:y", &["com.c.Sink:w"]),
        ]);
        let starts = Regex::new("Source").unwrap();
        let dests = Regex::new("Sink").unwrap();
        let paths = multi_to_multi_bfs(&g, &[starts], &[dests]);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec![
            "com.a.Source1:x".to_string(),
            "com.b.Mid:y".to_string(),
            "com.c.Sink:w".to_string(),
        ]));
        assert!(paths.contains(&vec![
            "com.a.Source2:z".to_string(),
            "com.b.Mid:y".to_string(),
            "com.c.Sink:w".to_string(),
        ]));
    }

    #[test]
    fn test_multi_to_multi_bfs_regex_is_case_sensitive() {
        let g = graph(&[("com.a.Source:x", &["com.b.Sink:y"])]);
        let starts = Regex::new("source").unwrap();
        let dests = Regex::new("sink").unwrap();
        assert!(multi_to_multi_bfs(&g, &[starts], &[dests]).is_empty());
    }

    #[test]
    fn test_multi_to_multi_bfs_start_matching_dest() {
        // A node matching both regexes yields the trivial self path.
        let g = graph(&[("com.a.Source:x", &["com.b.Mid:y"])]);
        let starts = Regex::new("Source").unwrap();
        let dests = Regex::new("Source").unwrap();
        let paths = multi_to_multi_bfs(&g, &[starts], &[dests]);
        assert_eq!(paths, vec![vec!["com.a.Source:x"]]);
    }

    #[test]
    fn test_format_paths_empty() {
        assert_eq!(format_paths(&[], Format::Printed), "");
    }

    #[test]
    fn test_format_paths_single_path() {
        let paths = vec![vec!["a:A".to_string(), "b:B".to_string()]];
        assert_eq!(
            format_paths(&paths, Format::Printed),
            "a:A -> b:B\n\"a:A\"\n\"b:B\"\n\n"
        );
    }

    #[test]
    fn test_format_paths_singleton_path() {
        let paths = vec![vec!["a:A".to_string()]];
        assert_eq!(
            format_paths(&paths, Format::Printed),
            "a:A -> a:A\n\"a:A\"\n\n"
        );
    }

    #[test]
    fn test_format_paths_multiple_paths() {
        let paths = vec![
            vec!["a".to_string(), "b".to_string()],
            vec!["c".to_string()],
        ];
        assert_eq!(
            format_paths(&paths, Format::Printed),
            "a -> b\n\"a\"\n\"b\"\n\nc -> c\n\"c\"\n\n"
        );
    }

    #[test]
    #[should_panic(expected = "Failed to parse regex")]
    fn test_handle_trace_bad_start_regex() {
        let _ = handle_trace(
            "(".to_string(),
            "foo".to_string(),
            false,
            false,
            Format::Printed,
            vec![],
            false,
        );
    }

    #[test]
    #[should_panic(expected = "Failed to parse regex")]
    fn test_handle_trace_bad_end_regex() {
        let _ = handle_trace(
            "foo".to_string(),
            "(".to_string(),
            false,
            false,
            Format::Printed,
            vec![],
            false,
        );
    }

    #[test]
    fn test_handle_trace_no_results() {
        // An unreadable APK is silently dropped, leaving no call graphs to
        // search; the command warns on stderr and succeeds.
        let result = handle_trace(
            "onCreate".to_string(),
            "sendTextMessage".to_string(),
            false,
            false,
            Format::Printed,
            vec![PathBuf::from("/nonexistent/does-not-exist.apk")],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_trace_no_apks() {
        assert!(
            handle_trace(
                "a".to_string(),
                "b".to_string(),
                false,
                false,
                Format::Printed,
                vec![],
                false,
            )
            .is_ok()
        );
    }

    fn temp_file(content: &str, name: &str) -> PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_resolve_patterns_positional() {
        let patterns = resolve_patterns("onCreate", false).unwrap();
        assert_eq!(patterns, vec!["onCreate".to_string()]);
    }

    #[test]
    fn test_resolve_patterns_from_file() {
        let path = temp_file("onCreate\nloadUrl\n", "apkhound_trace_src_a.txt");
        let patterns = resolve_patterns(&path.to_string_lossy(), true).unwrap();
        assert_eq!(
            patterns,
            vec!["onCreate".to_string(), "loadUrl".to_string()]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_resolve_patterns_from_file_strips_blank_and_crlf() {
        let path = temp_file("onCreate\r\n\r\n  loadUrl  \n", "apkhound_trace_src_b.txt");
        let patterns = resolve_patterns(&path.to_string_lossy(), true).unwrap();
        assert_eq!(
            patterns,
            vec!["onCreate".to_string(), "loadUrl".to_string()]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_resolve_patterns_from_file_unescaped_lines_kept_as_is() {
        // A line containing a metacharacter stays a single pattern; no
        // alternation is introduced until matching runs.
        let path = temp_file("com\\.example\\..*", "apkhound_trace_src_c.txt");
        let patterns = resolve_patterns(&path.to_string_lossy(), true).unwrap();
        assert_eq!(patterns, vec!["com\\.example\\..*".to_string()]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_resolve_patterns_missing_file() {
        let err = resolve_patterns("/does/not/exist.txt", true).unwrap_err();
        assert!(err.contains("Failed to read"));
    }

    #[test]
    fn test_resolve_patterns_empty_file() {
        let path = temp_file("", "apkhound_trace_empty.txt");
        let result = resolve_patterns(&path.to_string_lossy(), true);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_compile_patterns_multiple() {
        let regs = compile_patterns(&["onCreate".to_string(), "loadUrl".to_string()]);
        assert_eq!(regs.len(), 2);
        assert!(regs[0].is_match("com.x:onCreate"));
        assert!(!regs[0].is_match("com.x:loadUrl"));
        assert!(regs[1].is_match("com.x:loadUrl"));
    }

    #[test]
    #[should_panic(expected = "Failed to parse regex")]
    fn test_compile_patterns_bad_regex() {
        let _ = compile_patterns(&["(".to_string()]);
    }

    #[test]
    fn test_multi_to_multi_bfs_multiple_start_regexes() {
        let g = graph(&[
            ("com.a.Source1:x", &["com.b.Mid:y"]),
            ("com.a.Source2:z", &["com.b.Mid:y"]),
            ("com.b.Mid:y", &["com.c.Sink:w"]),
        ]);
        let starts = [
            Regex::new("Source1").unwrap(),
            Regex::new("Source2").unwrap(),
        ];
        let dests = [Regex::new("Sink").unwrap()];
        let paths = multi_to_multi_bfs(&g, &starts, &dests);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_multi_to_multi_bfs_multiple_dest_regexes() {
        let g = graph(&[
            ("com.a.Source:x", &["com.b.Mid:y"]),
            ("com.b.Mid:y", &["com.c.Sink:z", "com.c.Other:w"]),
        ]);
        let starts = [Regex::new("Source").unwrap()];
        let dests = [Regex::new("Sink").unwrap(), Regex::new("Other").unwrap()];
        let paths = multi_to_multi_bfs(&g, &starts, &dests);
        assert_eq!(paths.len(), 2);
    }
}
