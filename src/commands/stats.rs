//! Handler for the `stats` subcommand — reports structural statistics for
//! one or more APKs.  When exactly two APKs are given, a metric diff
//! between them is also emitted (in `printed` and `json` formats).

use crate::compare::unpack_apk_classes;
use crate::stats::{
    ApkStats, ChangeCoverage, ChangeCoverageStats, MetricDiff, StatsDiff, compute_change_coverage,
    compute_stats, diff_stats,
};
use crate::utils::build_regex;
use clap::ValueEnum;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use serde::Serialize;
use smali::android::zip::ApkFile;
use smali::types::SmaliClass;
use std::path::PathBuf;
use tracing::error;

/// Output format for the statistics.
#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
pub enum StatsFormat {
    /// Human-readable text report.
    Printed,
    /// JSON.
    Json,
    /// CSV (one row per APK).
    Csv,
}

/// Per-APK analysis: aggregated [`ApkStats`] plus the unpacked class list,
/// kept so change-coverage can run purely in memory without re-parsing the
/// DEX files.
struct ApkAnalysis {
    classes: Vec<SmaliClass>,
    stats: ApkStats,
}

/// Top-level JSON document for the `stats` command.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct StatsReport {
    apks: Vec<ApkStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<StatsDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    change_coverage: Option<ChangeCoverageStats>,
}

/// Compute statistics for one or two APKs and render them in the requested
/// `format`.  A failed APK is a hard error; a class `filters` list restricts
/// which classes/methods/opcodes are counted.
///
/// Class unpacking happens exactly once per APK, up front and in parallel.
/// Every output section is fully computed before the first byte is printed,
/// so nothing is emitted while parsing is still in progress.
pub fn handle_stats(
    apks: Vec<PathBuf>,
    filters: Vec<String>,
    graph: bool,
    format: StatsFormat,
) -> Result<(), String> {
    let regex: Vec<Regex> = build_regex(&filters);

    let apk_results: Vec<(PathBuf, Result<ApkFile, _>)> = apks
        .par_iter()
        .map(|path| (path.clone(), ApkFile::from_file(path)))
        .collect();

    for (path, res) in &apk_results {
        if let Err(e) = res {
            error!("Error parsing apk {} due to reason: {e}", path.display());
            return Err(format!(
                "Error parsing apk {} due to reason: {e}",
                path.display()
            ));
        }
    }

    let analyses: Vec<ApkAnalysis> = apk_results
        .par_iter()
        .map(|(path, res)| {
            let apk = res.as_ref().expect("APK parse errors handled above");
            let classes = unpack_apk_classes(apk, &regex);
            let stats = compute_stats(apk, &classes, Some(path.as_path()), &regex, graph);
            ApkAnalysis { classes, stats }
        })
        .collect();

    match format {
        StatsFormat::Printed => {
            // Compute the diff and change coverage *before* printing anything
            // so the per-APK blocks do not beat the (in-memory) diff work.
            let (diff, coverage) = if analyses.len() == 2 {
                (
                    Some(diff_stats(&analyses[0].stats, &analyses[1].stats)),
                    Some(compute_change_coverage(
                        &analyses[0].classes,
                        &analyses[1].classes,
                    )),
                )
            } else {
                (None, None)
            };
            for analysis in &analyses {
                print!("{}", format_printed(&analysis.stats));
            }
            if let (Some(diff), Some(coverage)) = (diff, coverage) {
                print!("{}", format_diff_printed(&diff));
                print!("{}", format_change_coverage_printed(&coverage));
            }
            Ok(())
        }
        StatsFormat::Json => {
            let diff = if analyses.len() == 2 {
                Some(diff_stats(&analyses[0].stats, &analyses[1].stats))
            } else {
                None
            };
            let change_coverage = if analyses.len() == 2 {
                Some(compute_change_coverage(
                    &analyses[0].classes,
                    &analyses[1].classes,
                ))
            } else {
                None
            };
            let report = StatsReport {
                apks: analyses.iter().map(|a| a.stats.clone()).collect(),
                diff,
                change_coverage,
            };
            let json = serde_json::to_string_pretty(&report)
                .map_err(|e| format!("Failed to serialize statistics: {e}"))?;
            println!("{json}");
            Ok(())
        }
        StatsFormat::Csv => {
            if analyses.is_empty() {
                return Ok(());
            }
            let rows: Vec<Vec<(String, String)>> =
                analyses.iter().map(|a| flatten_stats(&a.stats)).collect();
            let header: Vec<&str> = rows[0].iter().map(|(key, _)| key.as_str()).collect();
            println!("{}", header.join(","));
            for row in rows {
                let values: Vec<&str> = row.iter().map(|(_, value)| value.as_str()).collect();
                println!("{}", values.join(","));
            }
            Ok(())
        }
    }
}

/// Render one APK's stats as a human-readable key/value report.
fn format_printed(s: &ApkStats) -> String {
    let path = s.path.clone().unwrap_or_else(|| "<unknown>".to_string());
    let hline = "=".repeat(60);
    let mut out = String::new();
    out.push_str(&hline);
    out.push('\n');
    out.push_str(&format!("{:^60}\n", format!("STATS {path}")));
    out.push_str(&hline);
    out.push('\n');

    kv(
        &mut out,
        "File size (bytes)",
        &s.file_size_bytes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "(unknown)".to_string()),
    );
    kv(&mut out, "DEX entries", &s.dex_entries.to_string());
    kv(&mut out, "Classes", &s.classes.to_string());
    kv(&mut out, "Methods", &s.methods.to_string());
    kv(&mut out, "Constructors", &s.constructors.to_string());
    kv(&mut out, "Instructions", &s.instructions.to_string());
    kv(
        &mut out,
        "Avg instructions / method",
        &format!("{:.2}", s.avg_method_instructions),
    );
    kv(
        &mut out,
        "Min instructions / method",
        &s.min_method_instructions.to_string(),
    );
    kv(
        &mut out,
        "Max instructions / method",
        &s.max_method_instructions.to_string(),
    );
    out.push('\n');

    if !s.methods_by_modifier.is_empty() {
        out.push_str("--- Methods by modifier ---\n");
        for (modifier, count) in &s.methods_by_modifier {
            kv(&mut out, modifier, &count.to_string());
        }
        out.push('\n');
    }

    out.push_str("--- Opcodes ---\n");
    for (name, count) in s.opcodes.entries() {
        kv(&mut out, name, &count.to_string());
    }
    out.push('\n');

    if !s.top_packages.is_empty() {
        out.push_str("--- Top packages ---\n");
        for package in &s.top_packages {
            kv(&mut out, &package.package, &package.classes.to_string());
        }
        out.push('\n');
    }

    if let Some(cg) = &s.call_graph {
        out.push_str("--- Call graph ---\n");
        kv(&mut out, "Nodes", &cg.nodes.to_string());
        kv(&mut out, "Edges", &cg.edges.to_string());
        kv(&mut out, "Max out-degree", &cg.max_out_degree.to_string());
        kv(&mut out, "Max in-degree", &cg.max_in_degree.to_string());
        kv(&mut out, "Isolated methods", &cg.isolated.to_string());
        kv(&mut out, "Density", &format!("{:.6}", cg.density));
        out.push('\n');
    }

    out
}

/// Render [`StatsDiff`] as an aligned table.
fn format_diff_printed(diff: &StatsDiff) -> String {
    let mut out = String::new();
    out.push_str("--- Diff (old -> new) ---\n");
    out.push_str(&format!(
        "  {:<32} {:>10} {:>10} {:>10} {:>12}\n",
        "metric", "old", "new", "delta", "%change"
    ));

    for (key, d) in &diff.metrics {
        diff_row(&mut out, key, d);
    }
    for (modifier, d) in &diff.methods_by_modifier {
        diff_row(&mut out, &format!("modifier.{modifier}"), d);
    }
    for (opcode, d) in &diff.opcodes {
        diff_row(&mut out, &format!("opcode.{opcode}"), d);
    }
    if let Some(cg) = &diff.call_graph {
        for (key, d) in cg {
            diff_row(&mut out, &format!("callgraph.{key}"), d);
        }
    }
    out
}

fn diff_row(out: &mut String, key: &str, d: &MetricDiff) {
    let pct = match d.percent_change {
        Some(p) if p >= 0.0 => format!("+{}%", fmt_num(p)),
        Some(p) => format!("{}%", fmt_num(p)),
        None => "n/a".to_string(),
    };
    let delta = if d.delta >= 0.0 {
        format!("+{}", fmt_num(d.delta))
    } else {
        fmt_num(d.delta)
    };
    out.push_str(&format!(
        "  {:<32} {:>10} {:>10} {:>10} {:>12}\n",
        key,
        fmt_num(d.old),
        fmt_num(d.new),
        delta,
        pct
    ));
}

/// Render [`ChangeCoverageStats`] as an aligned table.  `percent_changed` is
/// the share of distinct units (across both APKs) whose body changed.
fn format_change_coverage_printed(cov: &ChangeCoverageStats) -> String {
    let mut out = String::new();
    out.push_str("--- Change coverage (old -> new) ---\n");
    out.push_str(&format!(
        "  {:<30} {:>8} {:>8} {:>8} {:>8} {:>10} {:>9} {:>9} {:>10}\n",
        "metric", "old", "new", "added", "removed", "modified", "unchanged", "union", "%changed"
    ));
    coverage_row(&mut out, "classes", &cov.classes);
    coverage_row(&mut out, "methods", &cov.methods);
    coverage_row(&mut out, "instructions", &cov.instructions);
    out.push('\n');
    out
}

fn coverage_row(out: &mut String, name: &str, cov: &ChangeCoverage) {
    out.push_str(&format!(
        "  {:<30} {:>8} {:>8} {:>8} {:>8} {:>10} {:>9} {:>9} {:>8.2}%\n",
        name,
        cov.old_total,
        cov.new_total,
        cov.added,
        cov.removed,
        cov.modified,
        cov.unchanged,
        cov.union_total,
        cov.percent_changed
    ));
}

/// Format a count as an integer when integral, two decimals otherwise.
fn fmt_num(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.2}")
    }
}

fn kv(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!("  {:<34} {:>14}\n", key, value));
}

/// Flatten an [`ApkStats`] into a fixed-order list of (column, value) pairs
/// for CSV output.  Every APK analyzed with the same flags produces exactly
/// the same columns.
fn flatten_stats(s: &ApkStats) -> Vec<(String, String)> {
    let mut out = vec![
        ("path".to_string(), s.path.clone().unwrap_or_default()),
        (
            "file_size_bytes".to_string(),
            s.file_size_bytes.map(|v| v.to_string()).unwrap_or_default(),
        ),
        ("dex_entries".to_string(), s.dex_entries.to_string()),
        ("classes".to_string(), s.classes.to_string()),
        ("methods".to_string(), s.methods.to_string()),
        ("constructors".to_string(), s.constructors.to_string()),
        ("instructions".to_string(), s.instructions.to_string()),
        (
            "avg_method_instructions".to_string(),
            format!("{:.2}", s.avg_method_instructions),
        ),
        (
            "min_method_instructions".to_string(),
            s.min_method_instructions.to_string(),
        ),
        (
            "max_method_instructions".to_string(),
            s.max_method_instructions.to_string(),
        ),
    ];
    for (modifier, count) in &s.methods_by_modifier {
        out.push((format!("methods_{modifier}"), count.to_string()));
    }
    for (opcode, count) in s.opcodes.entries() {
        out.push((format!("op_{opcode}"), count.to_string()));
    }
    if let Some(cg) = &s.call_graph {
        out.push(("cg_nodes".to_string(), cg.nodes.to_string()));
        out.push(("cg_edges".to_string(), cg.edges.to_string()));
        out.push((
            "cg_max_out_degree".to_string(),
            cg.max_out_degree.to_string(),
        ));
        out.push(("cg_max_in_degree".to_string(), cg.max_in_degree.to_string()));
        out.push(("cg_isolated".to_string(), cg.isolated.to_string()));
        out.push(("cg_density".to_string(), format!("{:.6}", cg.density)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{CallGraphStats, OpcodeStats};
    use std::collections::BTreeMap;

    fn sample_stats(path: &str) -> ApkStats {
        ApkStats {
            path: Some(path.to_string()),
            file_size_bytes: Some(123456),
            dex_entries: 2,
            classes: 42,
            methods: 100,
            constructors: 10,
            instructions: 500,
            avg_method_instructions: 5.0,
            min_method_instructions: 1,
            max_method_instructions: 40,
            methods_by_modifier: BTreeMap::from([
                ("public".to_string(), 60usize),
                ("static".to_string(), 20usize),
            ]),
            opcodes: OpcodeStats {
                invoke_virtual: 100,
                branches: 25,
                other: 1,
                total: 500,
                ..Default::default()
            },
            top_packages: vec![],
            call_graph: None,
        }
    }

    #[test]
    fn test_flatten_stats_columns_stable() {
        let rows = flatten_stats(&sample_stats("app.apk"));
        let keys: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"path"));
        assert!(keys.contains(&"classes"));
        assert!(keys.contains(&"methods_public"));
        assert!(keys.contains(&"op_invoke_virtual"));
        assert!(keys.contains(&"op_total"));
        assert!(!keys.contains(&"cg_nodes")); // no call graph requested
        // Same column set regardless of the row's values.
        let rows2 = flatten_stats(&sample_stats("other.apk"));
        let keys2: Vec<&str> = rows2.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, keys2);
    }

    #[test]
    fn test_flatten_stats_with_call_graph() {
        let mut s = sample_stats("app.apk");
        s.call_graph = Some(CallGraphStats {
            nodes: 100,
            edges: 250,
            max_out_degree: 12,
            max_in_degree: 9,
            isolated: 3,
            density: 0.025,
        });
        let rows = flatten_stats(&s);
        let keys: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"cg_nodes"));
        assert!(keys.contains(&"cg_density"));
    }

    #[test]
    fn test_format_printed_contains_headers() {
        let s = sample_stats("app.apk");
        let text = format_printed(&s);
        assert!(text.contains("STATS app.apk"));
        assert!(text.contains("Classes"));
        assert!(text.contains("Methods by modifier"));
        assert!(text.contains("Opcodes"));
    }

    #[test]
    fn test_format_diff_printed_contains_rows() {
        let old = sample_stats("old.apk");
        let new = sample_stats("new.apk");
        let diff = diff_stats(&old, &new);
        let text = format_diff_printed(&diff);
        assert!(text.contains("--- Diff (old -> new) ---"));
        assert!(text.contains("classes"));
        assert!(text.contains("%change"));
        assert!(text.contains("modifier.public"));
        assert!(text.contains("opcode.invoke_virtual"));
    }

    #[test]
    fn test_fmt_num_integral_and_fractional() {
        assert_eq!(fmt_num(42.0), "42");
        assert_eq!(fmt_num(5.5), "5.50");
    }

    #[test]
    fn test_format_change_coverage_printed_contains_rows() {
        let cov = ChangeCoverageStats {
            classes: ChangeCoverage {
                old_total: 100,
                new_total: 110,
                added: 12,
                removed: 2,
                modified: 5,
                unchanged: 93,
                union_total: 112,
                changed: 19,
                percent_changed: 19.0 / 112.0 * 100.0,
            },
            methods: ChangeCoverage {
                old_total: 500,
                new_total: 540,
                added: 60,
                removed: 20,
                modified: 30,
                unchanged: 450,
                union_total: 560,
                changed: 110,
                percent_changed: 110.0 / 560.0 * 100.0,
            },
            instructions: ChangeCoverage {
                old_total: 9000,
                new_total: 9500,
                added: 800,
                removed: 300,
                modified: 400,
                unchanged: 8700,
                union_total: 9800,
                changed: 1500,
                percent_changed: 15.0,
            },
        };
        let text = format_change_coverage_printed(&cov);
        assert!(text.contains("--- Change coverage (old -> new) ---"));
        assert!(text.contains("classes"));
        assert!(text.contains("methods"));
        assert!(text.contains("instructions"));
        assert!(text.contains("16.96%")); // 19 / 112
        assert!(text.contains("19.64%")); // 110 / 560
        assert!(text.contains("15.00%"));
    }

    #[test]
    fn test_diff_row_signs() {
        let mut out = String::new();
        diff_row(
            &mut out,
            "classes",
            &MetricDiff {
                old: 3400.0,
                new: 3456.0,
                delta: 56.0,
                percent_change: Some(1.647),
            },
        );
        assert!(out.contains("+56"));
        assert!(out.contains("+1.65%"));

        let mut out = String::new();
        diff_row(
            &mut out,
            "methods",
            &MetricDiff {
                old: 10.0,
                new: 8.0,
                delta: -2.0,
                percent_change: Some(-20.0),
            },
        );
        assert!(out.contains("-2"));
        assert!(out.contains("-20%"));

        let mut out = String::new();
        diff_row(
            &mut out,
            "new_features",
            &MetricDiff {
                old: 0.0,
                new: 5.0,
                delta: 5.0,
                percent_change: None,
            },
        );
        assert!(out.contains("n/a"));
    }
}
