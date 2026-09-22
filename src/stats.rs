//! APK statistics — compute structural metrics about the DEX code inside an
//! APK and (optionally) its call graph, plus a diff between two APKs.
//!
//! The heavy lifting reuses [`crate::compare::unpack_apk_classes`] for class
//! extraction and [`crate::callgraph::iterate_over_dex_files`] for the call
//! graph, so the numbers here mirror what `compare`/`trace` would report.

use regex::Regex;
use rustc_hash::FxHashMap;
use serde::Serialize;
use smali::android::zip::{ApkFile, is_top_level_dex_name};
use smali::smali_ops::DexOp;
use smali::types::{SmaliClass, SmaliMethod, SmaliOp};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::callgraph::iterate_over_dex_files;
use crate::compare::{construct_java_signature, functions_match};

/// A single top-level package (everything before the last `.` in a Java
/// type name) with the number of classes that live directly in it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PackageCount {
    pub package: String,
    pub classes: usize,
}

/// Opcode-family counts gathered while walking every method's instruction
/// stream.  The categories mirror the ones used by the matcher
/// (`matching.rs`), extended with a few extra families.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OpcodeStats {
    /// `invoke-virtual` / `invoke-virtual/range`
    pub invoke_virtual: usize,
    /// `invoke-super` / `invoke-super/range`
    pub invoke_super: usize,
    /// `invoke-direct` / `invoke-direct/range`
    pub invoke_direct: usize,
    /// `invoke-static` / `invoke-static/range`
    pub invoke_static: usize,
    /// `invoke-interface` / `invoke-interface/range`
    pub invoke_interface: usize,
    /// `invoke-polymorphic` / `invoke-polymorphic/range`
    pub invoke_polymorphic: usize,
    /// `invoke-custom` / `invoke-custom/range`
    pub invoke_custom: usize,
    /// `execute-inline` / `execute-inline/range`
    pub execute_inline: usize,
    /// `const-string` / `const-string/jumbo`
    pub string_constants: usize,
    /// instance & static field read/write ops (`iget*`/`iput*`/`sget*`/`sput*`)
    pub field_access: usize,
    /// conditional branches, gotos, and switches
    pub branches: usize,
    /// `return` / `return-void` / `return-wide` / `return-object`
    pub returns: usize,
    /// numeric & class constants (`const*`, `const-wide*`, `const-class`)
    pub const_ops: usize,
    /// register moves incl. `move-result*` and `move-exception`
    pub moves: usize,
    /// `monitor-enter` / `monitor-exit`
    pub monitors: usize,
    /// allocation ops (`new-instance`, `new-array`, `filled-new-array*`, `fill-array-data`)
    pub alloc_ops: usize,
    /// `throw` and friends
    pub exceptions: usize,
    /// array read/write ops (`aget*`/`aput*`) and `array-length`
    pub array_access: usize,
    /// floating point & long comparisons (`cmpl*`/`cmpg*`/`cmp-long`)
    pub comparisons: usize,
    /// `.catch` / `.catchall` directives
    pub try_catch: usize,
    /// any `DexOp` not falling into a family above
    pub other: usize,
    /// total number of dex opcodes across all methods (sum of all families)
    pub total: usize,
}

impl OpcodeStats {
    /// Iterate the counted families in a stable order.
    pub fn entries(&self) -> Vec<(&'static str, usize)> {
        vec![
            ("invoke_virtual", self.invoke_virtual),
            ("invoke_super", self.invoke_super),
            ("invoke_direct", self.invoke_direct),
            ("invoke_static", self.invoke_static),
            ("invoke_interface", self.invoke_interface),
            ("invoke_polymorphic", self.invoke_polymorphic),
            ("invoke_custom", self.invoke_custom),
            ("execute_inline", self.execute_inline),
            ("string_constants", self.string_constants),
            ("field_access", self.field_access),
            ("branches", self.branches),
            ("returns", self.returns),
            ("const_ops", self.const_ops),
            ("moves", self.moves),
            ("monitors", self.monitors),
            ("alloc_ops", self.alloc_ops),
            ("exceptions", self.exceptions),
            ("array_access", self.array_access),
            ("comparisons", self.comparisons),
            ("try_catch", self.try_catch),
            ("other", self.other),
            ("total", self.total),
        ]
    }
}

/// Call-graph metrics derived from the caller → callee map built by
/// [`crate::callgraph::iterate_over_dex_files`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CallGraphStats {
    /// number of methods that appear as callers (map keys)
    pub nodes: usize,
    /// number of distinct (caller, callee) invoke pairs
    pub edges: usize,
    /// largest number of callees invoked by a single method
    pub max_out_degree: usize,
    /// largest number of distinct callers that invoke one method
    pub max_in_degree: usize,
    /// methods that invoke nothing (no out-edges)
    pub isolated: usize,
    /// `edges / (nodes * (nodes - 1))`, 0 when `nodes <= 1`
    pub density: f64,
}

/// Structural statistics for one APK.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ApkStats {
    /// path of the APK this was computed from, when known
    pub path: Option<String>,
    /// size of the APK file in bytes, when the path is readable
    pub file_size_bytes: Option<u64>,
    /// number of top-level DEX entries in the APK
    pub dex_entries: usize,
    /// number of classes (after applying the class regex filters)
    pub classes: usize,
    /// number of methods across all matching classes
    pub methods: usize,
    /// number of constructor methods
    pub constructors: usize,
    /// number of dex opcodes across all methods
    pub instructions: usize,
    /// average opcodes per method
    pub avg_method_instructions: f64,
    /// smallest method body (in opcodes)
    pub min_method_instructions: usize,
    /// largest method body (in opcodes)
    pub max_method_instructions: usize,
    /// method counts grouped by Java modifier, e.g. `public`, `static`
    pub methods_by_modifier: BTreeMap<String, usize>,
    /// opcode-family breakdown
    pub opcodes: OpcodeStats,
    /// the packages with the most classes (top 10)
    pub top_packages: Vec<PackageCount>,
    /// call-graph metrics, only present when requested
    pub call_graph: Option<CallGraphStats>,
}

/// Difference between two [`ApkStats`] for a single scalar metric.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MetricDiff {
    pub old: f64,
    pub new: f64,
    pub delta: f64,
    /// percentage change relative to `old`; `None` when `old` is zero (the
    /// change is undefined / infinite)
    pub percent_change: Option<f64>,
}

/// Diff between two [`ApkStats`] values, keyed by metric name.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct StatsDiff {
    /// top-level scalar metrics
    pub metrics: BTreeMap<String, MetricDiff>,
    /// per-modifier method count diffs
    pub methods_by_modifier: BTreeMap<String, MetricDiff>,
    /// per-opcode-family count diffs
    pub opcodes: BTreeMap<String, MetricDiff>,
    /// call-graph diffs, only when both APKs were analyzed with the graph
    pub call_graph: Option<BTreeMap<String, MetricDiff>>,
}

/// Change coverage for a single unit type (classes, methods, instructions)
/// measured between two APKs.
///
/// A unit is *unchanged* when it exists in both APKs with an identical body
/// (method bodies are compared opcode-by-opcode via
/// [`functions_match`](crate::compare::functions_match)).  Everything else
/// counts as *added* (only in the new APK), *removed* (only in the old APK),
/// or *modified* (present in both but different).  `union_total` is the
/// number of distinct units across both APKs, and `percent_changed` is
/// `changed / union_total`, so it always lands between 0 and 100%.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ChangeCoverage {
    /// units present in the old APK
    pub old_total: usize,
    /// units present in the new APK
    pub new_total: usize,
    /// units that only exist in the new APK
    pub added: usize,
    /// units that only existed in the old APK
    pub removed: usize,
    /// units present in both APKs with a different body
    pub modified: usize,
    /// units present in both APKs with an identical body
    pub unchanged: usize,
    /// distinct units across both APKs (`unchanged + changed`)
    pub union_total: usize,
    /// `added + removed + modified` (always `union_total - unchanged`)
    pub changed: usize,
    /// `changed / union_total * 100`, 0 when the union is empty
    pub percent_changed: f64,
}

/// Change coverage by unit type between two APKs.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ChangeCoverageStats {
    pub classes: ChangeCoverage,
    pub methods: ChangeCoverage,
    pub instructions: ChangeCoverage,
}

/// Aggregate over a filtered set of classes, before merging with
/// APK-level and call-graph numbers.
struct ClassStats {
    classes: usize,
    methods: usize,
    constructors: usize,
    instructions: usize,
    min_method_instructions: usize,
    max_method_instructions: usize,
    methods_by_modifier: BTreeMap<String, usize>,
    opcodes: OpcodeStats,
    top_packages: Vec<PackageCount>,
}

impl Default for ClassStats {
    fn default() -> Self {
        ClassStats {
            classes: 0,
            methods: 0,
            constructors: 0,
            instructions: 0,
            // Sentinel so the per-method min() picks up real opcode counts;
            // rewritten to 0 in compute_stats when there are no methods.
            min_method_instructions: usize::MAX,
            max_method_instructions: 0,
            methods_by_modifier: BTreeMap::new(),
            opcodes: OpcodeStats::default(),
            top_packages: Vec::new(),
        }
    }
}

impl ClassStats {
    /// Name of the package a Java type belongs to, mapping the unnamed
    /// default package to `"(default)"`.
    fn package_of(java: &str) -> String {
        match java.rfind('.') {
            Some(i) => java[..i].to_string(),
            None => "(default)".to_string(),
        }
    }
}

/// Walk every method of every class, accumulating opcode-family and method
/// statistics into `ClassStats`.
fn collect_class_stats(classes: &[SmaliClass], out: &mut ClassStats) {
    out.classes += classes.len();

    let mut pkg_counts: BTreeMap<String, usize> = BTreeMap::new();
    for class in classes {
        let java = class.name.as_java_type();
        *pkg_counts.entry(ClassStats::package_of(&java)).or_default() += 1;
        for method in &class.methods {
            out.methods += 1;
            if method.constructor {
                out.constructors += 1;
            }
            for modifier in &method.modifiers {
                *out.methods_by_modifier
                    .entry(modifier.to_str().to_string())
                    .or_default() += 1;
            }
            let mut method_instructions = 0usize;
            for op in &method.ops {
                match op {
                    SmaliOp::Op(dop) => {
                        method_instructions += 1;
                        classify_opcode(dop, &mut out.opcodes);
                    }
                    SmaliOp::Catch(_) => out.opcodes.try_catch += 1,
                    _ => {}
                }
            }
            out.instructions += method_instructions;
            out.min_method_instructions = out.min_method_instructions.min(method_instructions);
            out.max_method_instructions = out.max_method_instructions.max(method_instructions);
        }
    }

    let mut pkgs: Vec<(String, usize)> = pkg_counts.into_iter().collect();
    pkgs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out.top_packages = pkgs
        .into_iter()
        .take(10)
        .map(|(package, classes)| PackageCount { package, classes })
        .collect();
}

/// Bucket a single dex opcode into the matching counter.
fn classify_opcode(dop: &DexOp, out: &mut OpcodeStats) {
    use DexOp::*;
    match dop {
        InvokeVirtual { .. } | InvokeVirtualRange { .. } => out.invoke_virtual += 1,
        InvokeSuper { .. } | InvokeSuperRange { .. } => out.invoke_super += 1,
        InvokeDirect { .. } | InvokeDirectRange { .. } => out.invoke_direct += 1,
        InvokeStatic { .. } | InvokeStaticRange { .. } => out.invoke_static += 1,
        InvokeInterface { .. } | InvokeInterfaceRange { .. } => out.invoke_interface += 1,
        InvokePolymorphic { .. } | InvokePolymorphicRange { .. } => out.invoke_polymorphic += 1,
        InvokeCustom { .. } | InvokeCustomRange { .. } => out.invoke_custom += 1,
        ExecuteInline { .. } | ExecuteInlineRange { .. } => out.execute_inline += 1,
        ConstString { .. } | ConstStringJumbo { .. } => out.string_constants += 1,
        // Instance & static field access.
        IGet { .. }
        | IGetWide { .. }
        | IGetObject { .. }
        | IGetBoolean { .. }
        | IGetByte { .. }
        | IGetChar { .. }
        | IGetShort { .. }
        | IPut { .. }
        | IPutWide { .. }
        | IPutObject { .. }
        | IPutBoolean { .. }
        | IPutByte { .. }
        | IPutChar { .. }
        | IPutShort { .. }
        | SGet { .. }
        | SGetWide { .. }
        | SGetObject { .. }
        | SGetBoolean { .. }
        | SGetByte { .. }
        | SGetChar { .. }
        | SGetShort { .. }
        | SPut { .. }
        | SPutWide { .. }
        | SPutObject { .. }
        | SPutBoolean { .. }
        | SPutByte { .. }
        | SPutChar { .. }
        | SPutShort { .. } => out.field_access += 1,
        // Branches & jumps.
        IfEq { .. }
        | IfNe { .. }
        | IfLt { .. }
        | IfGe { .. }
        | IfGt { .. }
        | IfLe { .. }
        | IfEqz { .. }
        | IfNez { .. }
        | IfLtz { .. }
        | IfGez { .. }
        | IfGtz { .. }
        | IfLez { .. }
        | Goto { .. }
        | Goto16 { .. }
        | Goto32 { .. }
        | PackedSwitch { .. }
        | SparseSwitch { .. } => out.branches += 1,
        ReturnVoid | Return { .. } | ReturnWide { .. } | ReturnObject { .. } => out.returns += 1,
        // Numeric & reference constants.
        Const4 { .. }
        | Const16 { .. }
        | Const { .. }
        | ConstHigh16 { .. }
        | ConstWide16 { .. }
        | ConstWide32 { .. }
        | ConstWide { .. }
        | ConstWideHigh16 { .. }
        | ConstClass { .. }
        | ConstMethodHandle { .. }
        | ConstMethodType { .. } => out.const_ops += 1,
        // Register moves.
        Move { .. }
        | MoveFrom16 { .. }
        | Move16 { .. }
        | MoveWide { .. }
        | MoveWideFrom16 { .. }
        | MoveWide16 { .. }
        | MoveObject { .. }
        | MoveObjectFrom16 { .. }
        | MoveObject16 { .. }
        | MoveResult { .. }
        | MoveResultWide { .. }
        | MoveResultObject { .. }
        | MoveException { .. } => out.moves += 1,
        MonitorEnter { .. } | MonitorExit { .. } => out.monitors += 1,
        // Allocation.
        NewInstance { .. }
        | NewArray { .. }
        | FilledNewArray { .. }
        | FilledNewArrayRange { .. }
        | FillArrayData { .. } => out.alloc_ops += 1,
        Throw { .. } | ThrowVerificationError { .. } => out.exceptions += 1,
        // Array access & length.
        AGet { .. }
        | AGetWide { .. }
        | AGetObject { .. }
        | AGetBoolean { .. }
        | AGetByte { .. }
        | AGetChar { .. }
        | AGetShort { .. }
        | APut { .. }
        | APutWide { .. }
        | APutObject { .. }
        | APutBoolean { .. }
        | APutByte { .. }
        | APutChar { .. }
        | APutShort { .. }
        | ArrayLength { .. } => out.array_access += 1,
        // Comparisons.
        CmplFloat { .. }
        | CmpgFloat { .. }
        | CmplDouble { .. }
        | CmpgDouble { .. }
        | CmpLong { .. } => out.comparisons += 1,
        _ => out.other += 1,
    }
}

/// Reduce a caller → callee map into summary [`CallGraphStats`].
pub fn call_graph_stats(graph: &FxHashMap<String, Vec<String>>) -> CallGraphStats {
    let nodes = graph.len();
    let edges: usize = graph.values().map(|v| v.len()).sum();
    let max_out_degree = graph.values().map(|v| v.len()).max().unwrap_or(0);

    let mut indegree: FxHashMap<&str, usize> = FxHashMap::default();
    for callees in graph.values() {
        for callee in callees {
            *indegree.entry(callee.as_str()).or_default() += 1;
        }
    }
    let max_in_degree = indegree.values().copied().max().unwrap_or(0);
    let isolated = graph.values().filter(|v| v.is_empty()).count();
    let density = if nodes <= 1 {
        0.0
    } else {
        edges as f64 / (nodes * (nodes - 1)) as f64
    };

    CallGraphStats {
        nodes,
        edges,
        max_out_degree,
        max_in_degree,
        isolated,
        density,
    }
}

/// Build an [`ApkStats`] for one APK from its already-unpacked (and
/// `filter`s-applied) classes.
///
/// `apk` is still needed for the top-level DEX entry count and, when
/// `include_graph` is set, the call-graph pass (which parses the DEX files
/// again by design — use `classes` to avoid re-unpacking classes).  When
/// `apk_path` is provided, its on-disk size is recorded.
pub fn compute_stats(
    apk: &ApkFile,
    classes: &[SmaliClass],
    apk_path: Option<&Path>,
    filters: &[Regex],
    include_graph: bool,
) -> ApkStats {
    let dex_entries = apk
        .entry_names()
        .filter(|name| is_top_level_dex_name(name))
        .count();

    let mut class_stats = ClassStats::default();
    collect_class_stats(classes, &mut class_stats);

    let avg_method_instructions = if class_stats.methods == 0 {
        0.0
    } else {
        class_stats.instructions as f64 / class_stats.methods as f64
    };

    let call_graph = if include_graph {
        Some(call_graph_stats(&iterate_over_dex_files(apk, filters)))
    } else {
        None
    };

    let file_size_bytes = apk_path
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len());

    class_stats.opcodes.total = class_stats.instructions;

    ApkStats {
        path: apk_path.map(|p| p.display().to_string()),
        file_size_bytes,
        dex_entries,
        classes: class_stats.classes,
        methods: class_stats.methods,
        constructors: class_stats.constructors,
        instructions: class_stats.instructions,
        avg_method_instructions,
        min_method_instructions: if class_stats.methods == 0 {
            0
        } else {
            class_stats.min_method_instructions
        },
        max_method_instructions: class_stats.max_method_instructions,
        methods_by_modifier: class_stats.methods_by_modifier,
        opcodes: class_stats.opcodes,
        top_packages: class_stats.top_packages,
        call_graph,
    }
}

fn metric_diff(old: f64, new: f64) -> MetricDiff {
    let delta = new - old;
    let percent_change = if old == 0.0 {
        if new == 0.0 { Some(0.0) } else { None }
    } else {
        Some(delta / old * 100.0)
    };
    MetricDiff {
        old,
        new,
        delta,
        percent_change,
    }
}

/// Diff two maps of counts, keeping the union of keys.
fn diff_counts(
    old: &BTreeMap<String, usize>,
    new: &BTreeMap<String, usize>,
) -> BTreeMap<String, MetricDiff> {
    let mut keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    keys.extend(old.keys().map(String::as_str));
    keys.extend(new.keys().map(String::as_str));

    keys.into_iter()
        .map(|key| {
            let old_val = old.get(key).copied().unwrap_or(0) as f64;
            let new_val = new.get(key).copied().unwrap_or(0) as f64;
            (key.to_string(), metric_diff(old_val, new_val))
        })
        .collect()
}

/// Compute the difference between the stats of two APKs.
pub fn diff_stats(old: &ApkStats, new: &ApkStats) -> StatsDiff {
    let mut metrics = BTreeMap::new();

    if let (Some(old_size), Some(new_size)) = (old.file_size_bytes, new.file_size_bytes) {
        metrics.insert(
            "file_size_bytes".to_string(),
            metric_diff(old_size as f64, new_size as f64),
        );
    }
    metrics.insert(
        "dex_entries".to_string(),
        metric_diff(old.dex_entries as f64, new.dex_entries as f64),
    );
    metrics.insert(
        "classes".to_string(),
        metric_diff(old.classes as f64, new.classes as f64),
    );
    metrics.insert(
        "methods".to_string(),
        metric_diff(old.methods as f64, new.methods as f64),
    );
    metrics.insert(
        "constructors".to_string(),
        metric_diff(old.constructors as f64, new.constructors as f64),
    );
    metrics.insert(
        "instructions".to_string(),
        metric_diff(old.instructions as f64, new.instructions as f64),
    );
    metrics.insert(
        "avg_method_instructions".to_string(),
        metric_diff(old.avg_method_instructions, new.avg_method_instructions),
    );
    metrics.insert(
        "min_method_instructions".to_string(),
        metric_diff(
            old.min_method_instructions as f64,
            new.min_method_instructions as f64,
        ),
    );
    metrics.insert(
        "max_method_instructions".to_string(),
        metric_diff(
            old.max_method_instructions as f64,
            new.max_method_instructions as f64,
        ),
    );

    let opcodes: BTreeMap<String, usize> = old
        .opcodes
        .entries()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let new_opcodes: BTreeMap<String, usize> = new
        .opcodes
        .entries()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    let call_graph = match (&old.call_graph, &new.call_graph) {
        (Some(old_cg), Some(new_cg)) => {
            let mut cg = BTreeMap::new();
            cg.insert(
                "nodes".to_string(),
                metric_diff(old_cg.nodes as f64, new_cg.nodes as f64),
            );
            cg.insert(
                "edges".to_string(),
                metric_diff(old_cg.edges as f64, new_cg.edges as f64),
            );
            cg.insert(
                "max_out_degree".to_string(),
                metric_diff(old_cg.max_out_degree as f64, new_cg.max_out_degree as f64),
            );
            cg.insert(
                "max_in_degree".to_string(),
                metric_diff(old_cg.max_in_degree as f64, new_cg.max_in_degree as f64),
            );
            cg.insert(
                "isolated".to_string(),
                metric_diff(old_cg.isolated as f64, new_cg.isolated as f64),
            );
            cg.insert(
                "density".to_string(),
                metric_diff(old_cg.density, new_cg.density),
            );
            Some(cg)
        }
        _ => None,
    };

    StatsDiff {
        metrics,
        methods_by_modifier: diff_counts(&old.methods_by_modifier, &new.methods_by_modifier),
        opcodes: diff_counts(&opcodes, &new_opcodes),
        call_graph,
    }
}

/// Number of real dex opcodes (`DexOp`) in a method body, mirroring how
/// `instructions` is counted elsewhere in this module.
fn method_instructions(method: &SmaliMethod) -> usize {
    method
        .ops
        .iter()
        .filter(|op| matches!(op, SmaliOp::Op(_)))
        .count()
}

/// Assemble a [`ChangeCoverage`] from the per-category breakdown.
///
/// `union_total` is the number of distinct units across both APKs: a
/// *modified* unit exists on both sides yet counts once, so for classes and
/// methods (`modified` = count of units) the union is `unchanged + changed`,
/// which also holds for instructions where `modified` already sums the old
/// and new sides.
fn finish_coverage(
    old_total: usize,
    new_total: usize,
    added: usize,
    removed: usize,
    modified: usize,
    unchanged: usize,
) -> ChangeCoverage {
    let changed = added + removed + modified;
    let union_total = unchanged + changed;
    let percent_changed = if union_total == 0 {
        0.0
    } else {
        changed as f64 / union_total as f64 * 100.0
    };
    ChangeCoverage {
        old_total,
        new_total,
        added,
        removed,
        modified,
        unchanged,
        union_total,
        changed,
        percent_changed,
    }
}

/// Core of [`compute_change_coverage`], operating on the already-unpacked
/// class lists so it can be unit-tested without real APK files.
fn change_coverage_from_classes(
    old_classes: &[SmaliClass],
    new_classes: &[SmaliClass],
) -> ChangeCoverageStats {
    // Class name -> class, for the class-level breakdown.
    let old_by_name: BTreeMap<String, &SmaliClass> = old_classes
        .iter()
        .map(|c| (c.name.as_java_type(), c))
        .collect();
    let new_by_name: BTreeMap<String, &SmaliClass> = new_classes
        .iter()
        .map(|c| (c.name.as_java_type(), c))
        .collect();

    // Method id -> (class, method): a method is identified by its full
    // signature (`construct_java_signature`), exactly like `compare`.
    let old_methods: BTreeMap<String, (&SmaliClass, &SmaliMethod)> = old_classes
        .iter()
        .flat_map(|class| {
            let class_name = class.name.as_java_type();
            class
                .methods
                .iter()
                .map(move |m| (construct_java_signature(class_name.clone(), m), (class, m)))
        })
        .collect();
    let new_methods: BTreeMap<String, (&SmaliClass, &SmaliMethod)> = new_classes
        .iter()
        .flat_map(|class| {
            let class_name = class.name.as_java_type();
            class
                .methods
                .iter()
                .map(move |m| (construct_java_signature(class_name.clone(), m), (class, m)))
        })
        .collect();

    // Instruction totals over each APK.
    let old_instructions: usize = old_classes
        .iter()
        .flat_map(|c| c.methods.iter())
        .map(method_instructions)
        .sum();
    let new_instructions: usize = new_classes
        .iter()
        .flat_map(|c| c.methods.iter())
        .map(method_instructions)
        .sum();

    // Method-level breakdown.
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut modified = 0usize;
    let mut added_ins = 0usize;
    let mut removed_ins = 0usize;
    let mut modified_old_ins = 0usize;
    let mut modified_new_ins = 0usize;
    let mut unchanged = 0usize;
    let mut unchanged_ins = 0usize;

    let method_keys: BTreeSet<String> = old_methods
        .keys()
        .chain(new_methods.keys())
        .cloned()
        .collect();
    for key in method_keys {
        match (old_methods.get(&key), new_methods.get(&key)) {
            (Some((_, old_m)), Some((_, new_m))) => {
                if functions_match(old_m, new_m) {
                    unchanged += 1;
                    unchanged_ins += method_instructions(old_m);
                } else {
                    modified += 1;
                    modified_old_ins += method_instructions(old_m);
                    modified_new_ins += method_instructions(new_m);
                }
            }
            (None, Some((_, new_m))) => {
                added += 1;
                added_ins += method_instructions(new_m);
            }
            (Some((_, old_m)), None) => {
                removed += 1;
                removed_ins += method_instructions(old_m);
            }
            (None, None) => unreachable!("key came from the union of both maps"),
        }
    }

    // Class-level breakdown.
    let mut classes_added = 0usize;
    let mut classes_removed = 0usize;
    let mut classes_modified = 0usize;
    let mut classes_unchanged = 0usize;

    let class_keys: BTreeSet<String> = old_by_name
        .keys()
        .chain(new_by_name.keys())
        .cloned()
        .collect();
    for name in class_keys {
        match (old_by_name.get(&name), new_by_name.get(&name)) {
            (None, Some(_)) => classes_added += 1,
            (Some(_), None) => classes_removed += 1,
            (Some(old_c), Some(new_c)) => {
                let old_sigs: BTreeSet<String> = old_c
                    .methods
                    .iter()
                    .map(|m| construct_java_signature(name.clone(), m))
                    .collect();
                let new_sigs: BTreeSet<String> = new_c
                    .methods
                    .iter()
                    .map(|m| construct_java_signature(name.clone(), m))
                    .collect();

                let mut class_modified = old_sigs != new_sigs;
                if !class_modified {
                    for new_m in &new_c.methods {
                        let sig = construct_java_signature(name.clone(), new_m);
                        let old_m = old_c
                            .methods
                            .iter()
                            .find(|om| construct_java_signature(name.clone(), om) == sig)
                            .expect("signature sets are equal");
                        if !functions_match(old_m, new_m) {
                            class_modified = true;
                            break;
                        }
                    }
                }
                if class_modified {
                    classes_modified += 1;
                } else {
                    classes_unchanged += 1;
                }
            }
            (None, None) => unreachable!("key came from the union of both maps"),
        }
    }

    ChangeCoverageStats {
        classes: finish_coverage(
            old_classes.len(),
            new_classes.len(),
            classes_added,
            classes_removed,
            classes_modified,
            classes_unchanged,
        ),
        methods: finish_coverage(
            old_methods.len(),
            new_methods.len(),
            added,
            removed,
            modified,
            unchanged,
        ),
        instructions: finish_coverage(
            old_instructions,
            new_instructions,
            added_ins,
            removed_ins,
            modified_old_ins + modified_new_ins,
            unchanged_ins,
        ),
    }
}

/// Compute the change coverage between two APKs' class sets: for classes,
/// methods, and instructions, the share of distinct units whose body changed
/// between the old and the new version.
///
/// The lists must already be unpacked and filtered (the caller owns the
/// unpacking so it happens exactly once per APK).  Method identity and
/// equality follow the `compare` command's rules (`construct_java_signature`
/// + [`functions_match`](crate::compare::functions_match)).
pub fn compute_change_coverage(
    old_classes: &[SmaliClass],
    new_classes: &[SmaliClass],
) -> ChangeCoverageStats {
    change_coverage_from_classes(old_classes, new_classes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smali::smali_ops::{DexOp, FieldRef, Label, MethodRef, SmaliRegister};
    use smali::types::{MethodSignature, Modifier, ObjectIdentifier, SmaliMethod};

    fn make_method(name: &str, sig: &str, ops: Vec<SmaliOp>) -> SmaliMethod {
        SmaliMethod {
            name: name.to_string(),
            modifiers: vec![],
            constructor: false,
            signature: MethodSignature::from_jni(sig),
            locals: 0,
            registers: None,
            params: vec![],
            annotations: vec![],
            ops,
        }
    }

    fn invoke(method: &str) -> SmaliOp {
        SmaliOp::Op(DexOp::InvokeVirtual {
            registers: vec![],
            method: MethodRef {
                class: "Ljava/lang/String;".to_string(),
                name: method.to_string(),
                descriptor: "()V".to_string(),
            },
        })
    }

    #[test]
    fn test_package_of_normal() {
        assert_eq!(
            ClassStats::package_of("com.example.MainActivity"),
            "com.example"
        );
    }

    #[test]
    fn test_package_of_deep() {
        assert_eq!(
            ClassStats::package_of("org.videolan.vlc.gui.MainActivity"),
            "org.videolan.vlc.gui"
        );
    }

    #[test]
    fn test_package_of_default() {
        assert_eq!(ClassStats::package_of("MainActivity"), "(default)");
    }

    #[test]
    fn test_classify_invoke_kinds() {
        let mut stats = OpcodeStats::default();
        classify_opcode(&DexOp::ReturnVoid, &mut stats);
        assert_eq!(stats.returns, 1);

        let mref = MethodRef {
            class: "Lcom/example/Target;".to_string(),
            name: "go".to_string(),
            descriptor: "()V".to_string(),
        };
        classify_opcode(
            &DexOp::InvokeStatic {
                registers: vec![],
                method: mref,
            },
            &mut stats,
        );
        assert_eq!(stats.invoke_static, 1);
        assert_eq!(stats.other, 0);
    }

    #[test]
    fn test_classify_field_and_branch() {
        let mut stats = OpcodeStats::default();
        classify_opcode(
            &DexOp::IGetObject {
                dest: SmaliRegister::Local(0),
                object: SmaliRegister::Local(1),
                field: FieldRef {
                    class: "Lcom/example/Foo;".to_string(),
                    name: "value".to_string(),
                    descriptor: "Ljava/lang/Object;".to_string(),
                },
            },
            &mut stats,
        );
        classify_opcode(
            &DexOp::Goto {
                offset: Label("L1".to_string()),
            },
            &mut stats,
        );
        assert_eq!(stats.field_access, 1);
        assert_eq!(stats.branches, 1);
    }

    #[test]
    fn test_collect_class_stats_counts() {
        let mut method_a = make_method(
            "foo",
            "()V",
            vec![
                invoke("helperA"),
                invoke("helperB"),
                SmaliOp::Op(DexOp::ReturnVoid),
            ],
        );
        method_a.modifiers = vec![Modifier::Public, Modifier::Static];

        let mut ctor = make_method("<init>", "()V", vec![SmaliOp::Op(DexOp::ReturnVoid)]);
        ctor.constructor = true;
        ctor.modifiers = vec![Modifier::Public];

        let class_a = SmaliClass {
            name: ObjectIdentifier::from_java_type("com.example.Foo"),
            modifiers: vec![],
            source: None,
            super_class: ObjectIdentifier::from_java_type("java.lang.Object"),
            implements: vec![],
            annotations: vec![],
            fields: vec![],
            methods: vec![method_a, ctor],
            file_path: None,
        };

        // Build a second class in the same package to exercise grouping.
        let class_b = SmaliClass {
            name: ObjectIdentifier::from_java_type("com.example.Bar"),
            ..class_a.clone()
        };

        let mut out = ClassStats::default();
        collect_class_stats(&[class_a, class_b], &mut out);

        assert_eq!(out.classes, 2);
        assert_eq!(out.methods, 4);
        assert_eq!(out.constructors, 2);
        assert_eq!(out.instructions, 8); // 2 classes x (3 + 1) op ops
        assert_eq!(out.min_method_instructions, 1);
        assert_eq!(out.max_method_instructions, 3);
        assert_eq!(out.methods_by_modifier.get("public"), Some(&4));
        assert_eq!(out.methods_by_modifier.get("static"), Some(&2));
        assert_eq!(out.top_packages.len(), 1);
        assert_eq!(out.top_packages[0].package, "com.example");
        assert_eq!(out.top_packages[0].classes, 2);
    }

    #[test]
    fn test_min_instructions_zero_for_empty_classes() {
        let mut out = ClassStats::default();
        collect_class_stats(&[], &mut out);
        // compute_stats rewrites the sentinel to 0 when there are no methods
        assert_eq!(out.min_method_instructions, usize::MAX);
    }

    #[test]
    fn test_call_graph_stats() {
        let mut graph: FxHashMap<String, Vec<String>> = FxHashMap::default();
        graph.insert(
            "a:x".to_string(),
            vec!["b:y".to_string(), "c:z".to_string()],
        );
        graph.insert("b:y".to_string(), vec!["c:z".to_string()]);
        graph.insert("d:q".to_string(), vec![]);

        let stats = call_graph_stats(&graph);
        assert_eq!(stats.nodes, 3);
        assert_eq!(stats.edges, 3);
        assert_eq!(stats.max_out_degree, 2);
        assert_eq!(stats.max_in_degree, 2); // c:z invoked by a:x and b:y
        assert_eq!(stats.isolated, 1);
        assert!((stats.density - 3.0 / 6.0).abs() < 1e-9);
    }

    #[test]
    fn test_call_graph_stats_empty() {
        let stats = call_graph_stats(&FxHashMap::default());
        assert_eq!(stats.nodes, 0);
        assert_eq!(stats.edges, 0);
        assert_eq!(stats.max_out_degree, 0);
        assert_eq!(stats.max_in_degree, 0);
        assert_eq!(stats.isolated, 0);
        assert_eq!(stats.density, 0.0);
    }

    #[test]
    fn test_metric_diff_percent() {
        let d = metric_diff(100.0, 125.0);
        assert_eq!(d.delta, 25.0);
        assert_eq!(d.percent_change, Some(25.0));
    }

    #[test]
    fn test_metric_diff_undefined_percent() {
        let d = metric_diff(0.0, 10.0);
        assert_eq!(d.delta, 10.0);
        assert_eq!(d.percent_change, None);
    }

    #[test]
    fn test_diff_counts_union_of_keys() {
        let mut old = BTreeMap::new();
        old.insert("a".to_string(), 1usize);
        let mut new = BTreeMap::new();
        new.insert("b".to_string(), 3usize);

        let diff = diff_counts(&old, &new);
        assert_eq!(diff.len(), 2);
        assert_eq!(diff["a"].delta, -1.0);
        assert_eq!(diff["b"].delta, 3.0);
        assert_eq!(diff["b"].percent_change, None); // old was 0
    }

    #[test]
    fn test_diff_stats_full() {
        // Build two fabricated ApkStats values and verify every diffable
        // metric is computed.
        let old = ApkStats {
            path: Some("old.apk".to_string()),
            file_size_bytes: Some(1000),
            dex_entries: 2,
            classes: 10,
            methods: 20,
            constructors: 5,
            instructions: 100,
            avg_method_instructions: 5.0,
            min_method_instructions: 1,
            max_method_instructions: 30,
            methods_by_modifier: BTreeMap::from([("public".to_string(), 15usize)]),
            opcodes: OpcodeStats {
                invoke_virtual: 40,
                total: 100,
                ..Default::default()
            },
            top_packages: vec![],
            call_graph: Some(CallGraphStats {
                nodes: 20,
                edges: 30,
                max_out_degree: 5,
                max_in_degree: 4,
                isolated: 2,
                density: 0.07,
            }),
        };
        let new = ApkStats {
            path: Some("new.apk".to_string()),
            file_size_bytes: Some(1200),
            dex_entries: 2,
            classes: 12,
            methods: 22,
            constructors: 5,
            instructions: 105,
            avg_method_instructions: 105.0 / 22.0,
            min_method_instructions: 1,
            max_method_instructions: 30,
            methods_by_modifier: BTreeMap::from([
                ("public".to_string(), 16usize),
                ("private".to_string(), 2usize),
            ]),
            opcodes: OpcodeStats {
                invoke_virtual: 42,
                total: 105,
                ..Default::default()
            },
            top_packages: vec![],
            call_graph: Some(CallGraphStats {
                nodes: 22,
                edges: 33,
                max_out_degree: 6,
                max_in_degree: 4,
                isolated: 1,
                density: 0.069,
            }),
        };

        let diff = diff_stats(&old, &new);
        assert_eq!(diff.metrics["classes"].delta, 2.0);
        assert_eq!(diff.metrics["methods"].delta, 2.0);
        assert_eq!(diff.metrics["instructions"].delta, 5.0);
        assert_eq!(diff.metrics["constructors"].delta, 0.0);
        assert_eq!(diff.methods_by_modifier["private"].delta, 2.0);
        assert_eq!(diff.opcodes["invoke_virtual"].delta, 2.0);
        let cg = diff.call_graph.as_ref().unwrap();
        assert_eq!(cg["nodes"].delta, 2.0);
        assert_eq!(cg["edges"].delta, 3.0);
    }

    fn make_class(name: &str, methods: Vec<SmaliMethod>) -> SmaliClass {
        SmaliClass {
            name: ObjectIdentifier::from_java_type(name),
            modifiers: vec![],
            source: None,
            super_class: ObjectIdentifier::from_java_type("java.lang.Object"),
            implements: vec![],
            annotations: vec![],
            fields: vec![],
            methods,
            file_path: None,
        }
    }

    #[test]
    fn test_change_coverage_identical() {
        let class = make_class(
            "com.example.Foo",
            vec![make_method(
                "m",
                "()V",
                vec![SmaliOp::Op(DexOp::ReturnVoid)],
            )],
        );
        let cov = change_coverage_from_classes(
            std::slice::from_ref(&class),
            std::slice::from_ref(&class),
        );

        for unit in [&cov.classes, &cov.methods, &cov.instructions] {
            assert_eq!(unit.unchanged, unit.union_total);
            assert_eq!(unit.changed, 0);
            assert_eq!(unit.percent_changed, 0.0);
        }
        assert_eq!(cov.classes.old_total, 1);
        assert_eq!(cov.classes.new_total, 1);
    }

    #[test]
    fn test_change_coverage_added_class() {
        let old = make_class(
            "com.example.Foo",
            vec![make_method(
                "m",
                "()V",
                vec![invoke("a"), invoke("b"), SmaliOp::Op(DexOp::ReturnVoid)],
            )],
        );
        let new_b = make_class(
            "com.example.Bar",
            vec![make_method(
                "n",
                "()V",
                vec![SmaliOp::Op(DexOp::ReturnVoid)],
            )],
        );

        let cov = change_coverage_from_classes(std::slice::from_ref(&old), &[old.clone(), new_b]);

        // Classes: 2 distinct, 1 added, 1 unchanged -> 50% changed.
        assert_eq!(cov.classes.added, 1);
        assert_eq!(cov.classes.unchanged, 1);
        assert_eq!(cov.classes.union_total, 2);
        assert_eq!(cov.classes.changed, 1);
        assert_eq!(cov.classes.percent_changed, 50.0);

        // Methods: 1 added, 1 unchanged.
        assert_eq!(cov.methods.added, 1);
        assert_eq!(cov.methods.unchanged, 1);
        assert_eq!(cov.methods.union_total, 2);
        assert_eq!(cov.methods.percent_changed, 50.0);

        // Instructions: old total 3, new total 4, unchanged 3 -> union 4,
        // changed 1 -> 25%.
        assert_eq!(cov.instructions.added, 1);
        assert_eq!(cov.instructions.unchanged, 3);
        assert_eq!(cov.instructions.union_total, 4);
        assert!((cov.instructions.percent_changed - 25.0).abs() < 1e-9);
    }

    #[test]
    fn test_change_coverage_removed_method_changes_class() {
        let mut old = make_class(
            "com.example.Foo",
            vec![make_method(
                "a",
                "()V",
                vec![SmaliOp::Op(DexOp::ReturnVoid)],
            )],
        );
        old.methods.push(make_method(
            "b",
            "()V",
            vec![SmaliOp::Op(DexOp::ReturnVoid)],
        ));

        let new = make_class(
            "com.example.Foo",
            vec![make_method(
                "a",
                "()V",
                vec![SmaliOp::Op(DexOp::ReturnVoid)],
            )],
        );

        let cov = change_coverage_from_classes(&[old], &[new]);

        assert_eq!(cov.classes.removed, 0);
        assert_eq!(cov.classes.modified, 1);
        assert_eq!(cov.classes.unchanged, 0);
        assert_eq!(cov.classes.percent_changed, 100.0);

        // Method b vanished; method a survived unchanged.
        assert_eq!(cov.methods.removed, 1);
        assert_eq!(cov.methods.unchanged, 1);
        assert_eq!(cov.methods.union_total, 2);
        assert_eq!(cov.methods.changed, 1);
        assert_eq!(cov.methods.percent_changed, 50.0);
    }

    #[test]
    fn test_change_coverage_modified_method_body() {
        let old = make_class(
            "com.example.Foo",
            vec![make_method(
                "m",
                "()V",
                vec![SmaliOp::Op(DexOp::ReturnVoid)],
            )],
        );
        let new = make_class(
            "com.example.Foo",
            vec![make_method(
                "m",
                "()V",
                vec![invoke("a"), SmaliOp::Op(DexOp::ReturnVoid)],
            )],
        );

        let cov = change_coverage_from_classes(&[old], &[new]);

        assert_eq!(cov.classes.modified, 1);
        assert_eq!(cov.classes.unchanged, 0);

        assert_eq!(cov.methods.modified, 1);
        assert_eq!(cov.methods.unchanged, 0);
        assert_eq!(cov.methods.old_total, 1);
        assert_eq!(cov.methods.new_total, 1);
        assert_eq!(cov.methods.percent_changed, 100.0);

        // Modified methods count their instructions from BOTH versions.
        assert_eq!(cov.instructions.modified, 1 + 2); // old 1 + new 2
        assert_eq!(cov.instructions.changed, 3);
        assert_eq!(cov.instructions.union_total, 3);
        assert_eq!(cov.instructions.percent_changed, 100.0);
    }

    #[test]
    fn test_change_coverage_mixed() {
        // old: A (methods a1, a2 unchanged), B (method b modified)
        // new: A' (a1, a2 unchanged), B' (method b' modified body),
        //      C (brand new)
        let method_a1 = make_method("a1", "()V", vec![SmaliOp::Op(DexOp::ReturnVoid)]);
        let method_a2 = make_method(
            "a2",
            "()I",
            vec![SmaliOp::Op(DexOp::Const4 {
                dest: SmaliRegister::Local(0),
                value: 1,
            })],
        );
        let method_b_old = make_method("b", "()V", vec![SmaliOp::Op(DexOp::ReturnVoid)]);
        let method_b_new = make_method(
            "b",
            "()V",
            vec![invoke("helper"), SmaliOp::Op(DexOp::ReturnVoid)],
        );

        let old_a = make_class("com.example.A", vec![method_a1.clone(), method_a2.clone()]);
        let old_b = make_class("com.example.B", vec![method_b_old]);
        let new_a = make_class("com.example.A", vec![method_a1, method_a2]);
        let new_b = make_class("com.example.B", vec![method_b_new]);
        let new_c = make_class(
            "com.example.C",
            vec![make_method(
                "c1",
                "()V",
                vec![SmaliOp::Op(DexOp::ReturnVoid)],
            )],
        );

        let cov = change_coverage_from_classes(&[old_a, old_b], &[new_a, new_b, new_c]);

        assert_eq!(cov.classes.old_total, 2);
        assert_eq!(cov.classes.new_total, 3);
        assert_eq!(cov.classes.added, 1); // C
        assert_eq!(cov.classes.removed, 0);
        assert_eq!(cov.classes.modified, 1); // B
        assert_eq!(cov.classes.unchanged, 1); // A
        assert_eq!(cov.classes.union_total, 3);
        assert_eq!(cov.classes.changed, 2);
        let classes_pct = 2.0 / 3.0 * 100.0;
        assert!((cov.classes.percent_changed - classes_pct).abs() < 1e-9);

        assert_eq!(cov.methods.added, 1); // C.c1
        assert_eq!(cov.methods.removed, 0);
        assert_eq!(cov.methods.modified, 1); // B.b
        assert_eq!(cov.methods.unchanged, 2); // A.a1, A.a2
        assert_eq!(cov.methods.union_total, 4);
        assert_eq!(cov.methods.changed, 2);
        assert_eq!(cov.methods.percent_changed, 50.0);
    }

    #[test]
    fn test_change_coverage_empty() {
        let cov = change_coverage_from_classes(&[], &[]);
        assert_eq!(cov.classes.percent_changed, 0.0);
        assert_eq!(cov.methods.union_total, 0);
        assert_eq!(cov.instructions.changed, 0);
    }
}
