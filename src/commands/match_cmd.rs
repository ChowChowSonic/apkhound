//! Handler for the `match` subcommand — runs WL graph-kernel matching
//! between packages in two APKs and displays a results table or CSV.

use crate::compare::unpack_apk_classes;
use crate::matching::{MatchParams, MatchResult, compute_match_summary, pkg_display, run_match};
use crate::utils::build_regex;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use smali::android::zip::ApkFile;
use std::path::PathBuf;
use tracing::error;

#[derive(Clone)]
pub struct MatchConfig {
    pub threshold: f64,
    pub change_threshold: f64,
    pub wl_iterations: usize,
    pub csv: bool,
    pub show_details: bool,
    pub filters: Vec<String>,
    pub use_node_matching: bool,
    pub api_weight: f64,
    pub hier_weight: f64,
    pub string_weight: f64,
    pub match_obfuscated: bool,
    pub summary: bool,
    pub score_only: bool,
}

/// Run package matching between two APKs and output the results as either a
/// formatted table or CSV.  When `show_details` is set, per-package method
/// counts and match scores are also printed.
pub fn handle_match(old_apk: PathBuf, new_apk: PathBuf, cfg: MatchConfig) -> Result<(), String> {
    let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
        .par_iter()
        .map(ApkFile::from_file)
        .collect();
    match (&apks[0], &apks[1]) {
        (Ok(old), Ok(new)) => {
            let regex: Vec<Regex> = build_regex(&cfg.filters);
            let old_classes = unpack_apk_classes(old, &regex);
            let new_classes = unpack_apk_classes(new, &regex);

            let match_params = MatchParams {
                match_threshold: cfg.threshold,
                change_threshold: cfg.change_threshold,
                wl_iterations: cfg.wl_iterations,
                use_node_matching: cfg.use_node_matching,
                api_weight: cfg.api_weight,
                hier_weight: cfg.hier_weight,
                string_weight: cfg.string_weight,
            };
            let match_result = run_match(&old_classes, &new_classes, &match_params);

            if cfg.score_only {
                let summary = compute_match_summary(&match_result);
                println!("{:.4}", summary.app_change_distance);
                return Ok(());
            }

            let MatchResult {
                results,
                old_pkg_methods,
                new_pkg_methods,
            } = &match_result;

            if cfg.csv {
                println!("old_package,new_package,score,status");
                for (old_name, new_name, score, status) in results {
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
            } else if !cfg.summary {
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

                if cfg.show_details {
                    println!();
                    for (old_name, new_name, score, status) in results {
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

            if cfg.summary {
                let summary = compute_match_summary(&match_result);
                if cfg.csv {
                    println!();
                    println!(
                        "# Summary: Algorithm = Weisfeiler-Lehman (WL) Graph Kernel + API & String Jaccard"
                    );
                    println!(
                        "# Methodology: Method-weighted package similarity, where weight = max(old_methods, new_methods), change_distance = 1.0 - similarity"
                    );
                    println!("metric,value");
                    println!("change_distance,{:.4}", summary.app_change_distance);
                    println!("similarity_score,{:.4}", summary.app_similarity_score);
                    println!("unweighted_similarity,{:.4}", summary.unweighted_similarity);
                    println!("packages_total_union,{}", summary.packages_total_union);
                    println!("packages_matched,{}", summary.matched_packages);
                    println!("packages_changed,{}", summary.changed_packages);
                    println!("packages_removed,{}", summary.removed_packages);
                    println!("packages_added,{}", summary.added_packages);
                    println!(
                        "packages_matched_pct,{:.2}%",
                        summary.packages_matched_ratio * 100.0
                    );
                    println!(
                        "packages_changed_pct,{:.2}%",
                        summary.packages_changed_ratio * 100.0
                    );
                    println!(
                        "packages_removed_pct,{:.2}%",
                        summary.packages_removed_ratio * 100.0
                    );
                    println!(
                        "packages_added_pct,{:.2}%",
                        summary.packages_added_ratio * 100.0
                    );
                    println!(
                        "code_in_matched_pct,{:.2}%",
                        summary.code_in_matched_ratio * 100.0
                    );
                    println!(
                        "code_in_changed_pct,{:.2}%",
                        summary.code_in_changed_ratio * 100.0
                    );
                    println!(
                        "code_in_removed_pct,{:.2}%",
                        summary.code_in_removed_ratio * 100.0
                    );
                    println!(
                        "code_in_added_pct,{:.2}%",
                        summary.code_in_added_ratio * 100.0
                    );
                } else {
                    println!("============================================================");
                    println!("                  APPLICATION CHANGE SUMMARY                ");
                    println!("============================================================");
                    println!(
                        "  Algorithm:   Weisfeiler-Lehman (WL) Graph Kernel + API & String Jaccard"
                    );
                    println!("  Methodology: Method-weighted package similarity, where:");
                    println!("               • Package weight = max(old_methods, new_methods)");
                    println!(
                        "               • Weighted similarity = sum(score_i * weight_i) / sum(weight_i)"
                    );
                    println!(
                        "               • Change distance = 1.0 - weighted_similarity (0.0 = identical, 1.0 = disjoint)"
                    );
                    println!("------------------------------------------------------------");
                    println!(
                        "  Overall change distance:    {:.4} ({:.2}% changed)",
                        summary.app_change_distance,
                        summary.app_change_distance * 100.0
                    );
                    println!(
                        "  Overall similarity score:   {:.4} ({:.2}% similar)",
                        summary.app_similarity_score,
                        summary.app_similarity_score * 100.0
                    );
                    println!(
                        "  Unweighted mean similarity: {:.4}",
                        summary.unweighted_similarity
                    );
                    println!();
                    println!(
                        "--- Package breakdown (union: {}) ---",
                        summary.packages_total_union
                    );
                    println!(
                        "  Matched: {:>6} ({:>6.2}% of pkgs | {:>6.2}% of code)",
                        summary.matched_packages,
                        summary.packages_matched_ratio * 100.0,
                        summary.code_in_matched_ratio * 100.0
                    );
                    println!(
                        "  Changed: {:>6} ({:>6.2}% of pkgs | {:>6.2}% of code)",
                        summary.changed_packages,
                        summary.packages_changed_ratio * 100.0,
                        summary.code_in_changed_ratio * 100.0
                    );
                    println!(
                        "  Removed: {:>6} ({:>6.2}% of pkgs | {:>6.2}% of code)",
                        summary.removed_packages,
                        summary.packages_removed_ratio * 100.0,
                        summary.code_in_removed_ratio * 100.0
                    );
                    println!(
                        "  Added:   {:>6} ({:>6.2}% of pkgs | {:>6.2}% of code)",
                        summary.added_packages,
                        summary.packages_added_ratio * 100.0,
                        summary.code_in_added_ratio * 100.0
                    );
                    println!("============================================================");
                }
            }
            Ok(())
        }
        (Err(old), _) => {
            error!("Error parsing old apk: {old}");
            Err(format!("Error parsing old apk: {old}"))
        }
        (_, Err(new)) => {
            error!("Error parsing new apk: {new}");
            Err(format!("Error parsing new apk: {new}"))
        }
    }
}
