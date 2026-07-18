//! Handler for the `match` subcommand — runs WL graph-kernel matching
//! between packages in two APKs and displays a results table or CSV.

use crate::compare::unpack_apk_classes;
use crate::matching::{MatchResult, pkg_display, run_match};
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
}

/// Run package matching between two APKs and output the results as either a
/// formatted table or CSV.  When `show_details` is set, per-package method
/// counts and match scores are also printed.
pub fn handle_match(old_apk: PathBuf, new_apk: PathBuf, cfg: MatchConfig) -> Result<(), ()> {
    let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
        .par_iter()
        .map(ApkFile::from_file)
        .collect();
    if let Ok(new) = &apks[1]
        && let Ok(old) = &apks[0]
    {
        let regex: Vec<Regex> = build_regex(&cfg.filters);
        let old_classes = unpack_apk_classes(old, &regex);
        let new_classes = unpack_apk_classes(new, &regex);

        let MatchResult {
            results,
            old_pkg_methods,
            new_pkg_methods,
        } = run_match(
            &old_classes,
            &new_classes,
            cfg.threshold,
            cfg.change_threshold,
            cfg.wl_iterations,
        );

        if cfg.csv {
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

            if cfg.show_details {
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
                            let old_m: usize = old_pkg_methods.get(old_name).copied().unwrap_or(0);
                            let new_m: usize = new_pkg_methods.get(new_name).copied().unwrap_or(0);
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
        Ok(())
    } else if let Err(old) = &apks[0] {
        error!("Error parsing old apk: {old}");
        Err(())
    } else if let Err(new) = &apks[1] {
        error!("Error parsing new apk: {new}");
        Err(())
    } else {
        Err(())
    }
}
