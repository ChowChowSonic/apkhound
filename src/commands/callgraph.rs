use crate::callgraph::iterate_over_dex_files;
use crate::utils::build_regex;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use smali::android::zip::ApkFile;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::error;

pub fn handle_callgraph(apk_path: Vec<PathBuf>, filters: Vec<String>) {
    let regex: Vec<Regex> = build_regex(&filters);

    let apk_results: Vec<Result<ApkFile, _>> =
        apk_path.par_iter().map(ApkFile::from_file).collect();

    let entries = apk_results
        .par_iter()
        .fold(
            HashMap::<String, Vec<String>>::new,
            |mut accum: HashMap<String, Vec<String>>, apk_result| {
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
        .reduce(HashMap::<String, Vec<String>>::new, |mut total, res| {
            res.iter().for_each(|(k, v)| {
                for y in v {
                    total.entry(k.to_string()).or_default().push(y.to_string());
                    let x = &mut total.entry(k.to_string()).or_default();
                    x.sort();
                    x.dedup();
                }
            });
            total
        });

    println!("digraph {{");
    entries.iter().for_each(|x| {
        for y in x.1 {
            println!("\"{}\" -> \"{}\"; ", x.0, y);
        }
    });
    println!("}}");
}
