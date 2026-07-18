//! Handler for the `callgraph` subcommand — extracts a call graph from one
//! or more APK files and prints it as a Graphviz DOT digraph.

use crate::callgraph::iterate_over_dex_files;
use crate::utils::build_regex;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use rustc_hash::FxHashMap;
use smali::android::zip::ApkFile;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use tracing::error;

/// Run the call-graph extraction across the given APK paths and print a
/// DOT digraph to stdout.  Optional `filters` restrict which classes are
/// included.
pub fn handle_callgraph(apk_path: Vec<PathBuf>, filters: Vec<String>) {
    let regex: Vec<Regex> = build_regex(&filters);

    let apk_results: Vec<Result<ApkFile, _>> =
        apk_path.par_iter().map(ApkFile::from_file).collect();

    let entries = apk_results
        .par_iter()
        .fold(
            FxHashMap::<String, Vec<String>>::default,
            |mut accum: FxHashMap<String, Vec<String>>, apk_result| {
                if let Ok(apk) = apk_result {
                    let res = iterate_over_dex_files(apk, &regex);
                    res.iter().for_each(|(key, val)| {
                        for y in val {
                            accum
                                .entry(key.to_string())
                                .and_modify(|tmp| tmp.push(y.to_string()))
                                .or_default()
                                .push(y.to_string());
                        }
                    });
                } else if let Err(e) = apk_result {
                    error!("Failed to parse APK file: {e}");
                }
                accum
            },
        )
        .reduce(
            FxHashMap::<String, Vec<String>>::default,
            |mut total, res| {
                res.iter().for_each(|(k, v)| {
                    for y in v {
                        total.entry(k.to_string()).or_default().push(y.to_string());
                        let x = &mut total.entry(k.to_string()).or_default();
                        x.sort();
                        x.dedup();
                    }
                });
                total
            },
        );

    let mut buf = BufWriter::new(std::io::stdout().lock());
    let _ = writeln!(buf, "digraph {{");
    for (src, targets) in &entries {
        for tgt in targets {
            let _ = writeln!(buf, "\"{}\" -> \"{}\"; ", src, tgt);
        }
    }
    let _ = writeln!(buf, "}}");
}
