mod callgraph;
mod compare;
mod matching;

mod utils;
use crate::callgraph::iterate_over_dex_files;
use crate::compare::{
    EditType, dump_changes_between_classes, find_changes_between_classes, unpack_apk_classes,
};
use crate::matching::{MatchResult, pkg_display, run_match};
use crate::utils::extract_manifest;
use clap::Parser;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use smali::android::binary_xml::{self, AndroidManifest};
use smali::android::zip::ApkFile;
use smali::types::SmaliClass;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::error;
use tracing::trace;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
enum Commands {
    /// Extract a call graph from an APK
    Callgraph {
        /// Path to the APK file
        apk_path: Vec<PathBuf>,
        /// Regex filter for class names (can be specified multiple times)
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
    },
    /// Compare two APKs and list class-level additions, removals, and changes
    Compare {
        /// Path to the original APK
        old_apk: PathBuf,
        /// Path to the modified APK
        new_apk: PathBuf,
        /// Regex filter for class names (can be specified multiple times)
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
    },
    /// Extract changed method smali to a directory
    Extract {
        /// Path to the original APK
        old_apk: PathBuf,
        /// Path to the modified APK
        new_apk: PathBuf,
        /// Directory to write extracted smali files to
        output_dir: PathBuf,
        /// Regex filter for class names (can be specified multiple times)
        #[arg(short = 'f', long = "filterclass")]
        class_filters: Vec<String>,
        /// Regex filter for method signatures (can be specified multiple times)
        #[arg(short = 's', long = "filtersmali")]
        smali_filters: Vec<String>,
    },
    /// Match packages across two APKs using graph isomorphism
    #[command(name = "match")]
    Match {
        /// Path to the original APK
        old_apk: PathBuf,
        /// Path to the modified APK
        new_apk: PathBuf,
        /// Similarity threshold to consider packages a match
        #[arg(short = 't', long = "threshold", default_value_t = 0.8)]
        threshold: f64,
        /// Minimum similarity to consider two packages related
        #[arg(long = "change-threshold", default_value_t = 0.0)]
        change_threshold: f64,
        /// Number of Weisfeiler-Lehman refinement iterations
        #[arg(long = "wl-iterations", default_value_t = 3)]
        wl_iterations: usize,
        /// Output in CSV format instead of a formatted table
        #[arg(long = "csv")]
        csv: bool,
        /// Show method counts for matched/changed packages
        #[arg(short = 'd', long = "show-details")]
        show_details: bool,
        /// Regex filter for class names (can be specified multiple times)
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
    },
    Permissions {
        old_apk: PathBuf,
        new_apk: Option<PathBuf>,
    },
}

fn build_regex(filters: &[String]) -> Vec<Regex> {
    let mut regex: Vec<Regex> = Vec::new();
    for x in filters {
        let regex_val = Regex::from_str(x);
        if let Ok(r) = regex_val {
            regex.push(r);
        } else if let Err(e) = regex_val {
            error!("Failed to parse regex {x:?} due to reason: {e}");
        }
    }
    regex
}

fn main() {
    tracing_subscriber::fmt()
        //    .with_max_level(LevelFilter::INFO)
        .with_writer(std::io::stderr)
        .init();
    let args = Commands::parse();
    match args {
        Commands::Callgraph { apk_path, filters } => {
            let regex: Vec<Regex> = build_regex(&filters);

            let apk_results: Vec<Result<ApkFile, _>> =
                apk_path.par_iter().map(ApkFile::from_file).collect();

            let entries = apk_results
                .par_iter()
                .fold(
                    HashMap::<String, Vec<String>>::new,
                    |mut accum: HashMap<String, Vec<String>>, apk_result| {
                        if let Ok(apk) = apk_result {
                            let res = iterate_over_dex_files(&apk, &regex);
                            //println!("digraph {{");
                            res.iter().for_each(|(key, val)| {
                                for y in val {
                                    accum
                                        .entry(key.to_string())
                                        .and_modify(|tmp| tmp.push(y.to_string()))
                                        .or_default()
                                        .push(y.to_string());
                                    //println!("\"{}\" -> \"{}\"; ", x.0, y)
                                }
                            });
                            //println!("}}");
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
                            let mut x = &mut total.entry(k.to_string()).or_default();
                            x.sort();
                            x.dedup();
                            //println!("\"{}\" -> \"{}\"; ", x.0, y)
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
        Commands::Compare {
            old_apk,
            new_apk,
            filters,
        } => {
            let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
                .par_iter()
                .map(ApkFile::from_file)
                .collect();
            if let Ok(new) = &apks[1]
                && let Ok(old) = &apks[0]
            {
                let regex: Vec<Regex> = build_regex(&filters);
                let old_classes = unpack_apk_classes(old, &regex)
                    .par_iter()
                    .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    })
                    .reduce(HashMap::new, |mut accum, mut res| {
                        accum.extend(res.drain());
                        accum
                    });
                let new_classes = unpack_apk_classes(new, &regex)
                    .par_iter()
                    .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    })
                    .reduce(HashMap::new, |mut accum, mut res| {
                        accum.extend(res.drain());
                        accum
                    });
                let res = find_changes_between_classes(new_classes, old_classes);
                for x in res {
                    match x {
                        EditType::Change(x) => println!("CHANGED: {x}"),
                        EditType::Addition(x) => println!("ADDED: {x}"),
                        EditType::Remove(x) => println!("REMOVED: {x}"),
                    }
                }
            } else if let Err(old) = &apks[0] {
                error!("Error parsing old apk: {old}");
            } else if let Err(new) = &apks[1] {
                error!("Error parsing new apk: {new}");
            }
        }

        Commands::Extract {
            old_apk,
            new_apk,
            output_dir,
            class_filters,
            smali_filters,
        } => {
            let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
                .par_iter()
                .map(ApkFile::from_file)
                .collect();
            if let Ok(new) = &apks[1]
                && let Ok(old) = &apks[0]
            {
                let regex: Vec<Regex> = build_regex(&class_filters);
                let smali_regex: Vec<Regex> = build_regex(&smali_filters);
                let old_classes = unpack_apk_classes(old, &regex)
                    .par_iter()
                    .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    })
                    .reduce(HashMap::new, |mut accum, mut res| {
                        accum.extend(res.drain());
                        accum
                    });
                let new_classes = unpack_apk_classes(new, &regex)
                    .par_iter()
                    .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    })
                    .reduce(HashMap::new, |mut accum, mut res| {
                        accum.extend(res.drain());
                        accum
                    });
                let _ = dump_changes_between_classes(
                    new_classes,
                    old_classes,
                    &output_dir,
                    &smali_regex,
                );
            } else if let Err(old) = &apks[0] {
                error!("Error parsing old apk: {old}");
            } else if let Err(new) = &apks[1] {
                error!("Error parsing new apk: {new}");
            }
        }
        Commands::Match {
            old_apk,
            new_apk,
            threshold,
            change_threshold,
            wl_iterations,
            csv,
            show_details,
            filters,
        } => {
            let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
                .par_iter()
                .map(ApkFile::from_file)
                .collect();
            if let Ok(new) = &apks[1]
                && let Ok(old) = &apks[0]
            {
                let regex: Vec<Regex> = build_regex(&filters);
                let old_classes = unpack_apk_classes(old, &regex);
                let new_classes = unpack_apk_classes(new, &regex);

                let MatchResult {
                    results,
                    old_pkg_methods,
                    new_pkg_methods,
                } = run_match(
                    &old_classes,
                    &new_classes,
                    threshold,
                    change_threshold,
                    wl_iterations,
                );

                if csv {
                    println!("old_package,new_package,score,status");
                    for (old_name, new_name, score, status) in &results {
                        let score_str = if *score <= 0.0 {
                            "---".to_string()
                        } else {
                            format!("{:.2}", score)
                        };
                        println!(
                            "{},{},{},{}",
                            pkg_display(old_name),
                            pkg_display(new_name),
                            score_str,
                            status
                        );
                    }
                } else {
                    let disp_rows: Vec<(String, String, String, &str)> = results
                        .iter()
                        .map(|(on, nn, score, status)| {
                            let score_str = if *score <= 0.0 {
                                "---".to_string()
                            } else {
                                format!("{:.2}", score)
                            };
                            (pkg_display(on), pkg_display(nn), score_str, status.as_str())
                        })
                        .collect();

                    let cw0 = disp_rows
                        .iter()
                        .map(|r| r.0.len())
                        .max()
                        .unwrap_or(0)
                        .max("Package (old)".len());
                    let cw1 = disp_rows
                        .iter()
                        .map(|r| r.1.len())
                        .max()
                        .unwrap_or(0)
                        .max("Package (new)".len());
                    let cw2 = disp_rows
                        .iter()
                        .map(|r| r.2.len())
                        .max()
                        .unwrap_or(0)
                        .max("Score".len());
                    let cw3 = disp_rows
                        .iter()
                        .map(|r| r.3.len())
                        .max()
                        .unwrap_or(0)
                        .max("Status".len());

                    let sep = "  ";
                    let lpad = |s: &str, w: usize| {
                        if s.len() >= w {
                            s.to_string()
                        } else {
                            format!("{}{}", " ".repeat(w - s.len()), s)
                        }
                    };
                    let rpad = |s: &str, w: usize| {
                        if s.len() >= w {
                            s.to_string()
                        } else {
                            format!("{}{}", s, " ".repeat(w - s.len()))
                        }
                    };

                    println!(
                        "{}{}{}{}{}{}{}",
                        rpad("Package (old)", cw0),
                        sep,
                        rpad("Package (new)", cw1),
                        sep,
                        lpad("Score", cw2),
                        sep,
                        rpad("Status", cw3)
                    );
                    println!("{}", "-".repeat(cw0 + cw1 + cw2 + cw3 + sep.len() * 3));

                    for (old_pkg, new_pkg, score_str, status) in &disp_rows {
                        println!(
                            "{}{}{}{}{}{}{}",
                            rpad(old_pkg, cw0),
                            sep,
                            rpad(new_pkg, cw1),
                            sep,
                            lpad(score_str, cw2),
                            sep,
                            rpad(status, cw3)
                        );
                    }

                    if show_details {
                        println!();
                        for (old_name, new_name, score, status) in &results {
                            let score_str = if *score <= 0.0 {
                                "---".to_string()
                            } else {
                                format!("{:.2}", score)
                            };
                            match status.as_str() {
                                "REMOVED" => {
                                    println!("  {}  (removed)", pkg_display(old_name));
                                }
                                "NEW" => {
                                    println!("  {}  (added)", pkg_display(new_name));
                                }
                                _ => {
                                    let old_m: usize =
                                        old_pkg_methods.get(old_name).copied().unwrap_or(0);
                                    let new_m: usize =
                                        new_pkg_methods.get(new_name).copied().unwrap_or(0);
                                    println!(
                                        "  {}  <->  {}  (methods {}->{} | score={})",
                                        pkg_display(old_name),
                                        pkg_display(new_name),
                                        old_m,
                                        new_m,
                                        score_str,
                                    );
                                }
                            }
                        }
                    }
                }
            } else if let Err(old) = &apks[0] {
                error!("Error parsing old apk: {old}");
            } else if let Err(new) = &apks[1] {
                error!("Error parsing new apk: {new}");
            }
        }
        Commands::Permissions { old_apk, new_apk } => {
            if let Some(new_res) = new_apk {
                let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_res]
                    .par_iter()
                    .map(ApkFile::from_file)
                    .collect();
                if let Ok(old) = &apks[0]
                    && let Ok(new) = &apks[1]
                {
                    let old_manifest_res = extract_manifest(old);
                    let new_manifest_res = extract_manifest(new);
                    if let Ok(old_doc) = &old_manifest_res
                        && let Ok(new_doc) = &new_manifest_res
                    {
                        let old_permissions = old_doc.uses_permissions();
                        let new_permissions = new_doc.uses_permissions();
                        let mut old_attributes: Vec<String> = Vec::new();
                        let mut new_attributes: Vec<String> = Vec::new();
                        for (x, a) in old_permissions.iter().zip(&new_permissions) {
                            for y in x.attributes.iter().filter_map(|t| t.raw_value.clone()) {
                                old_attributes.push(y);
                            }
                            for y in a.attributes.iter().filter_map(|t| t.raw_value.clone()) {
                                new_attributes.push(y);
                            }
                        }
                        for (x, y) in old_attributes.iter().zip(&new_attributes) {
                            if !new_attributes.contains(&x) {
                                println!("PERMISSION REMOVED: {}", x);
                            }
                            if !old_attributes.contains(&y) {
                                println!("PERMISSION ADDED: {}", y);
                            }
                        }
                    } else if let Err(old) = old_manifest_res {
                        error!("Error parsing old AndroidManifest: {old}");
                    } else if let Err(new) = new_manifest_res {
                        error!("Error parsing new AndroidManifest: {new}");
                    }
                } else if let Err(old) = &apks[0] {
                    error!("Unable to parse old APK due to reason: {old}");
                } else if let Err(new) = &apks[1] {
                    error!("Unable to parse new APK due to reason: {new}");
                };
            } else if let Ok(apk) = ApkFile::from_file(old_apk) {
                //TODO: Parse manifest from single APK file and print it
                let manifest: AndroidManifest =
                    extract_manifest(&apk).expect("Error when trying to retrieve android manifest");
                for x in manifest.uses_permissions() {
                    for y in x.attributes.iter().filter_map(|t| t.raw_value.clone()) {
                        println!("{y:?}");
                    }
                }
            } //ends outer if-let 
        }
    } //ends main
}
