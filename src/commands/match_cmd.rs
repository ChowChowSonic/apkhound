//! Handler for the `match` subcommand — runs WL graph-kernel matching
//! between packages in two APKs and displays a results table or CSV.

use crate::compare::unpack_apk_classes;
use crate::matching::{
    ClassMatchDebug, Feature, MatchParams, MatchResult, PackageMatchDebug, compute_match_summary,
    compute_package_debug_info, debug_class_matches, pkg_display, run_match,
};
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
    pub blacklist: Vec<String>,
    pub use_node_matching: bool,
    pub api_weight: f64,
    pub hier_weight: f64,
    pub string_weight: f64,
    pub match_obfuscated: bool,
    pub summary: bool,
    pub score_only: bool,
    pub exclude_features: Vec<Feature>,
    pub debug: bool,
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
            let blacklist_regex: Vec<Regex> = build_regex(&cfg.blacklist);
            let old_classes = unpack_apk_classes(old, &regex, &blacklist_regex);
            let new_classes = unpack_apk_classes(new, &regex, &blacklist_regex);

            let match_params = MatchParams {
                match_threshold: cfg.threshold,
                change_threshold: cfg.change_threshold,
                wl_iterations: cfg.wl_iterations,
                use_node_matching: cfg.use_node_matching,
                api_weight: cfg.api_weight,
                hier_weight: cfg.hier_weight,
                string_weight: cfg.string_weight,
                excluded_features: cfg.exclude_features,
            };
            let match_result = run_match(&old_classes, &new_classes, &match_params);

            if cfg.score_only {
                let summary = compute_match_summary(&match_result);
                println!("{:.4}", summary.app_change_distance);
                return Ok(());
            }

            if cfg.debug {
                let pkg_debug = compute_package_debug_info(
                    &old_classes,
                    &new_classes,
                    &match_params,
                    &match_result,
                );
                let class_debug = debug_class_matches(&old_classes, &new_classes, &match_result);
                print_debug_report(&pkg_debug, &class_debug);
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
                            "EMPTY" => {
                                println!(
                                    "  {}  <->  {}  (empty)",
                                    pkg_display(old_name),
                                    pkg_display(new_name)
                                );
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
                    println!("packages_empty,{}", summary.empty_packages);
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
                        "packages_empty_pct,{:.2}%",
                        summary.packages_empty_ratio * 100.0
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
                    println!(
                        "code_in_empty_pct,{:.2}%",
                        summary.code_in_empty_ratio * 100.0
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
                    println!(
                        "  Empty:   {:>6} ({:>6.2}% of pkgs | {:>6.2}% of code)",
                        summary.empty_packages,
                        summary.packages_empty_ratio * 100.0,
                        summary.code_in_empty_ratio * 100.0
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

/// Print an in-depth debugging report of package-level and class-level matching.
pub fn print_debug_report(pkg_debug: &[PackageMatchDebug], class_debug: &[ClassMatchDebug]) {
    println!("================================================================================");
    println!("                            MATCHING DEBUG REPORT                               ");
    println!("================================================================================");
    println!();
    println!("--------------------------------------------------------------------------------");
    println!("PACKAGE MATCHING BREAKDOWN ({} packages)", pkg_debug.len());
    println!("--------------------------------------------------------------------------------");

    for p in pkg_debug {
        println!(
            "Package: {} -> {}",
            pkg_display(&p.old_package),
            pkg_display(&p.new_package)
        );
        println!("  Status: {} | Final Score: {:.4}", p.status, p.total_score);
        println!("  Reason: {}", p.match_reason);
        if p.status != "EMPTY" && p.old_package != "---" && p.new_package != "---" {
            println!("  Score Components:");
            println!("    - Weisfeiler-Lehman (WL): {:.4}", p.matched_wl_score);
            println!("    - API Calls (Jaccard):   {:.4}", p.matched_api_score);
            println!("    - String Constants:      {:.4}", p.matched_string_score);
            println!("    - Hierarchy Factor:      {:.4}", p.matched_hier_factor);
        }
        if !p.top_alternatives.is_empty() {
            println!("  Top Alternative Packages (Runner-ups):");
            for (idx, alt) in p.top_alternatives.iter().enumerate() {
                println!(
                    "    {}. {} (Total: {:.4} | WL: {:.4}, API: {:.4}, STR: {:.4}, HIER: {:.4})",
                    idx + 1,
                    pkg_display(&alt.package_name),
                    alt.total_score,
                    alt.wl_score,
                    alt.api_score,
                    alt.string_score,
                    alt.hier_factor,
                );
            }
        }
        println!();
    }

    println!("--------------------------------------------------------------------------------");
    println!("CLASS MATCHING BREAKDOWN ({} classes)", class_debug.len());
    println!("--------------------------------------------------------------------------------");

    for c in class_debug {
        let old_name = c.old_class.as_deref().unwrap_or("---");
        let new_name = c.new_class.as_deref().unwrap_or("---");
        println!("Class: {} -> {}", old_name, new_name);
        println!("  Status: {} | Match Score: {:.4}", c.status, c.score);
        println!("  Reason: {}", c.match_reason);

        if let Some(prof) = &c.old_profile {
            println!("  Old Class Profile (19 Dimensions):");
            println!(
                "    - Superclass:         {}",
                prof.super_class.as_deref().unwrap_or("(none)")
            );
            println!("    - Methods:            {}", prof.method_count);
            println!("    - Instructions:       {}", prof.num_instructions);
            println!("    - Registers:          {}", prof.register_count);
            println!("    - Branches (ops):     {}", prof.has_branches);
            println!("    - Try/Catch blocks:   {}", prof.try_catch_count);
            println!("    - Field Accesses:     {}", prof.field_access_count);
            println!("    - Method Parameters:  {}", prof.num_params);
            println!("    - Constructors:       {}", prof.is_constructor_count);
            println!(
                "    - Invokes:            virtual: {}, static: {}, direct: {}, interface: {}",
                prof.invoke_virtual_count,
                prof.invoke_static_count,
                prof.invoke_direct_count,
                prof.invoke_interface_count
            );
            println!(
                "    - External Calls:     android: {}, java: {}, kotlin: {}, other: {}",
                prof.ext_android_count,
                prof.ext_java_count,
                prof.ext_kotlin_count,
                prof.ext_other_count
            );
            println!("    - Distinct API Calls: {}", prof.distinct_api_calls);
            println!("    - Distinct Strings:   {}", prof.distinct_strings);
        }

        if let Some(prof) = &c.new_profile {
            println!("  New Class Profile (19 Dimensions):");
            println!(
                "    - Superclass:         {}",
                prof.super_class.as_deref().unwrap_or("(none)")
            );
            println!("    - Methods:            {}", prof.method_count);
            println!("    - Instructions:       {}", prof.num_instructions);
            println!("    - Registers:          {}", prof.register_count);
            println!("    - Branches (ops):     {}", prof.has_branches);
            println!("    - Try/Catch blocks:   {}", prof.try_catch_count);
            println!("    - Field Accesses:     {}", prof.field_access_count);
            println!("    - Method Parameters:  {}", prof.num_params);
            println!("    - Constructors:       {}", prof.is_constructor_count);
            println!(
                "    - Invokes:            virtual: {}, static: {}, direct: {}, interface: {}",
                prof.invoke_virtual_count,
                prof.invoke_static_count,
                prof.invoke_direct_count,
                prof.invoke_interface_count
            );
            println!(
                "    - External Calls:     android: {}, java: {}, kotlin: {}, other: {}",
                prof.ext_android_count,
                prof.ext_java_count,
                prof.ext_kotlin_count,
                prof.ext_other_count
            );
            println!("    - Distinct API Calls: {}", prof.distinct_api_calls);
            println!("    - Distinct Strings:   {}", prof.distinct_strings);
        }

        if !c.top_alternatives.is_empty() {
            println!("  Top Alternative Classes (Runner-ups):");
            for (idx, alt) in c.top_alternatives.iter().enumerate() {
                println!(
                    "    {}. {} (Total: {:.4} | API: {:.4}, String: {:.4}, Superclass: {:.4}, Method Count: {:.4})",
                    idx + 1,
                    alt.class_name,
                    alt.total_score,
                    alt.api_similarity,
                    alt.string_similarity,
                    alt.super_class_similarity,
                    alt.method_count_similarity,
                );
            }
        }
        println!();
    }
    println!("================================================================================");
}
