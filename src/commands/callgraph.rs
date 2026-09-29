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
/// DOT digraph to stdout. Optional `filters` restrict which classes are
/// included. When `match_obfuscated` is true and two APKs are given, runs
/// matching analysis first and normalizes obfuscated node names to their
/// matched counterparts.
pub fn handle_callgraph(
    apk_path: Vec<PathBuf>,
    filters: Vec<String>,
    match_obfuscated: bool,
) -> Result<(), String> {
    let regex: Vec<Regex> = build_regex(&filters);

    let apk_results: Vec<Result<ApkFile, _>> =
        apk_path.par_iter().map(ApkFile::from_file).collect();

    let match_set = if match_obfuscated
        && apk_results.len() >= 2
        && let (Ok(old), Ok(new)) = (&apk_results[0], &apk_results[1])
    {
        let match_params = crate::matching::MatchParams::default();
        let old_classes = crate::compare::unpack_apk_classes(old, &regex);
        let new_classes = crate::compare::unpack_apk_classes(new, &regex);
        Some(crate::matching::build_class_match_set(
            &old_classes,
            &new_classes,
            &match_params,
        ))
    } else {
        if match_obfuscated && apk_results.len() < 2 {
            tracing::info!(
                "--match-obfuscated specified with fewer than 2 APKs; skipping matching analysis"
            );
        }
        None
    };

    let normalize = |sig: &str| -> String {
        let (Some(ms), Some((cls, mth))) = (&match_set, sig.split_once(':')) else {
            return sig.to_string();
        };
        if let Some(old_cls) = ms.new_to_old.get(cls) {
            format!("{old_cls}:{mth}")
        } else {
            sig.to_string()
        }
    };

    let mut entries = apk_results
        .par_iter()
        .fold(
            FxHashMap::<String, Vec<String>>::default,
            |mut accum: FxHashMap<String, Vec<String>>, apk_result| {
                if let Ok(apk) = apk_result {
                    let res = iterate_over_dex_files(apk, &regex);
                    res.iter().for_each(|(key, val)| {
                        let norm_key = normalize(key);
                        let norm_vals = val.iter().map(|v| normalize(v));
                        accum.entry(norm_key).or_default().extend(norm_vals);
                    });
                } else if let Err(e) = apk_result {
                    error!("Failed to parse APK file: {e}");
                    panic!("Failed to parse APK file");
                }
                accum
            },
        )
        .reduce(
            FxHashMap::<String, Vec<String>>::default,
            |mut total, res| {
                for (k, v) in &res {
                    total
                        .entry(k.clone())
                        .or_default()
                        .extend(v.iter().cloned());
                }
                total
            },
        );

    for val in entries.values_mut() {
        val.sort();
        val.dedup();
    }

    let mut buf = BufWriter::new(std::io::stdout().lock());
    let _ = writeln!(buf, "digraph {{");
    for (src, targets) in &entries {
        for tgt in targets {
            let _ = writeln!(buf, "\"{}\" -> \"{}\"; ", src, tgt);
        }
    }
    let _ = writeln!(buf, "}}");

    if apk_results.iter().any(|r| r.is_err()) {
        Err("An error has occurred when parsing the apk results".to_string())
    } else {
        Ok(())
    }
}
