//! Weisfeiler-Lehman graph kernel matching across packages in two APKs.
//!
//! Builds a call-graph per package, extracts a 13-dimensional feature
//! vector per method, runs WL refinement to produce multi-level histogram
//! signatures, then performs greedy bipartite matching between packages.

use std::hash::{Hash, Hasher};

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use smali::smali_ops::DexOp;
use smali::types::{SmaliClass, SmaliMethod, SmaliOp};

/// A count of how many times each WL label appears at a given iteration.
pub type Histogram = FxHashMap<u64, usize>;

/// Bundles the WL histograms, per-node final labels, and adjacency of a
/// single package, so the matching layer can optionally run a node-label
/// consistency check in addition to histogram intersection.
pub struct WLSig {
    pub hists: Vec<Histogram>,
    pub final_labels: Vec<u64>,
    pub adjacency: Vec<Vec<usize>>,
}

type SigsMap = FxHashMap<String, WLSig>;

pub struct SideData<'a> {
    pub sigs: &'a SigsMap,
    pub names: &'a [String],
    pub no_graph: &'a [String],
}

/// A directed call graph for a single package.
/// Each node corresponds to a method; edges represent internal calls.
#[derive(Clone)]
pub struct PackageGraph {
    /// Adjacency list: for each node, the indices of methods it calls.
    pub adjacency: Vec<Vec<usize>>,
    /// 13-element feature vectors for each method node.
    pub features: Vec<[i32; 13]>,
}

/// The output of a matching run.
pub struct MatchResult {
    /// Each entry: `(old_package, new_package, similarity_score, status)`.
    /// Status is one of `MATCH`, `CHANGED`, `REMOVED`, or `NEW`.
    pub results: Vec<(String, String, f64, String)>,
    /// Number of methods per package in the old APK.
    pub old_pkg_methods: FxHashMap<String, usize>,
    /// Number of methods per package in the new APK.
    pub new_pkg_methods: FxHashMap<String, usize>,
}

const IDX_IN_DEGREE: usize = 0;
const IDX_OUT_DEGREE: usize = 1;
const IDX_EXT_ANDROID: usize = 2;
const IDX_EXT_JAVA: usize = 3;
const IDX_EXT_KOTLIN: usize = 4;
const IDX_EXT_OTHER: usize = 5;
const IDX_INVOKE_VIRTUAL: usize = 6;
const IDX_INVOKE_STATIC: usize = 7;
const IDX_INVOKE_DIRECT: usize = 8;
const IDX_INVOKE_INTERFACE: usize = 9;
const IDX_NUM_PARAMS: usize = 10;
const IDX_NUM_INSTRUCTIONS: usize = 11;
const IDX_HAS_BRANCHES: usize = 12;

fn get_package_name(jni_class: &str) -> Option<String> {
    let inner = jni_class.strip_prefix('L')?.strip_suffix(';')?;
    if let Some(pos) = inner.rfind('/') {
        Some(inner[..pos].to_string())
    } else {
        Some(String::new())
    }
}

/// Convert an internal (slash-separated) package name for display, mapping
/// an empty package to `"(default)"`.
pub fn pkg_display(pkg: &str) -> String {
    if pkg.is_empty() {
        "(default)".to_string()
    } else {
        pkg.replace('/', ".")
    }
}

fn categorize_external(jni_class: &str) -> &'static str {
    if jni_class.starts_with("Landroid/") {
        "android"
    } else if jni_class.starts_with("Landroidx/") {
        "androidx"
    } else if jni_class.starts_with("Ljava/") || jni_class.starts_with("Ljavax/") {
        "java"
    } else if jni_class.starts_with("Lkotlin/") || jni_class.starts_with("Lkotlinx/") {
        "kotlin"
    } else {
        "other"
    }
}

fn get_method_key(class_jni: &str, method: &SmaliMethod) -> String {
    format!(
        "{}->{}{}",
        class_jni,
        method.name,
        method.signature.to_jni()
    )
}

fn is_branch_op(dop: &DexOp) -> bool {
    matches!(
        dop,
        DexOp::IfEq { .. }
            | DexOp::IfNe { .. }
            | DexOp::IfLt { .. }
            | DexOp::IfGe { .. }
            | DexOp::IfGt { .. }
            | DexOp::IfLe { .. }
            | DexOp::IfEqz { .. }
            | DexOp::IfNez { .. }
            | DexOp::IfLtz { .. }
            | DexOp::IfGez { .. }
            | DexOp::IfGtz { .. }
            | DexOp::IfLez { .. }
            | DexOp::Goto { .. }
            | DexOp::Goto16 { .. }
            | DexOp::Goto32 { .. }
            | DexOp::PackedSwitch { .. }
            | DexOp::SparseSwitch { .. }
    )
}

fn extract_method_features(method: &SmaliMethod, package_name: &str) -> ([i32; 13], Vec<String>) {
    let mut features = [0i32; 13];

    features[IDX_NUM_PARAMS] = method.params.len() as i32;

    let mut internal_calls: Vec<String> = Vec::new();
    let mut out_degree = 0i32;
    let mut num_instructions = 0i32;
    let mut has_branches = 0i32;
    let mut invoke_virtual = 0i32;
    let mut invoke_static = 0i32;
    let mut invoke_direct = 0i32;
    let mut invoke_interface = 0i32;
    let mut ext_android = 0i32;
    let mut ext_java = 0i32;
    let mut ext_kotlin = 0i32;
    let mut ext_other = 0i32;

    for sop in &method.ops {
        let SmaliOp::Op(dop) = sop else {
            continue;
        };
        num_instructions += 1;

        if is_branch_op(dop) {
            has_branches = 1;
        }

        let (invoke_kind, mref_opt) = match dop {
            DexOp::InvokeVirtual { method, .. } | DexOp::InvokeVirtualRange { method, .. } => {
                ("virtual", Some(method))
            }
            DexOp::InvokeSuper { method, .. } | DexOp::InvokeSuperRange { method, .. } => {
                ("super", Some(method))
            }
            DexOp::InvokeDirect { method, .. } | DexOp::InvokeDirectRange { method, .. } => {
                ("direct", Some(method))
            }
            DexOp::InvokeStatic { method, .. } | DexOp::InvokeStaticRange { method, .. } => {
                ("static", Some(method))
            }
            DexOp::InvokeInterface { method, .. } | DexOp::InvokeInterfaceRange { method, .. } => {
                ("interface", Some(method))
            }
            DexOp::InvokePolymorphic { method, .. }
            | DexOp::InvokePolymorphicRange { method, .. } => ("polymorphic", Some(method)),
            _ => continue,
        };

        match invoke_kind {
            "virtual" | "super" => invoke_virtual += 1,
            "static" => invoke_static += 1,
            "direct" => invoke_direct += 1,
            "interface" => invoke_interface += 1,
            _ => {}
        }

        out_degree += 1;

        if let Some(mref) = mref_opt {
            let callee_key = format!("{}->{}{}", mref.class, mref.name, mref.descriptor);
            let callee_pkg = get_package_name(&mref.class);

            if callee_pkg.as_deref() == Some(package_name) {
                internal_calls.push(callee_key);
            } else {
                match categorize_external(&mref.class) {
                    "android" | "androidx" => ext_android += 1,
                    "java" => ext_java += 1,
                    "kotlin" => ext_kotlin += 1,
                    _ => ext_other += 1,
                }
            }
        }
    }

    features[IDX_OUT_DEGREE] = out_degree;
    features[IDX_NUM_INSTRUCTIONS] = num_instructions;
    features[IDX_HAS_BRANCHES] = has_branches;
    features[IDX_INVOKE_VIRTUAL] = invoke_virtual;
    features[IDX_INVOKE_STATIC] = invoke_static;
    features[IDX_INVOKE_DIRECT] = invoke_direct;
    features[IDX_INVOKE_INTERFACE] = invoke_interface;
    features[IDX_EXT_ANDROID] = ext_android;
    features[IDX_EXT_JAVA] = ext_java;
    features[IDX_EXT_KOTLIN] = ext_kotlin;
    features[IDX_EXT_OTHER] = ext_other;

    (features, internal_calls)
}

/// Partition a list of `SmaliClass` values by package, build a
/// `PackageGraph` (call graph + feature vectors) for each non-empty
/// package, and return the method counts per package.
pub fn build_package_graphs(
    classes: &[SmaliClass],
) -> (
    FxHashMap<String, Option<PackageGraph>>,
    FxHashMap<String, usize>,
) {
    let mut pkgs: FxHashMap<String, Vec<&SmaliClass>> = FxHashMap::default();
    for c in classes {
        let jni = c.name.as_jni_type();
        if let Some(pkg) = get_package_name(&jni) {
            pkgs.entry(pkg).or_default().push(c);
        }
    }

    let mut method_counts: FxHashMap<String, usize> = FxHashMap::default();
    let mut graph_data: FxHashMap<String, Option<PackageGraph>> = FxHashMap::default();
    for (pkg, cls_list) in &pkgs {
        let total_methods: usize = cls_list.iter().map(|c| c.methods.len()).sum();
        method_counts.insert((*pkg).clone(), total_methods);

        let mut methods: FxHashMap<String, &SmaliMethod> = FxHashMap::default();
        for cls in cls_list {
            let class_jni = cls.name.as_jni_type();
            for method in &cls.methods {
                let key = get_method_key(&class_jni, method);
                methods.insert(key, method);
            }
        }

        if methods.is_empty() {
            graph_data.insert((*pkg).clone(), None);
            continue;
        }

        let node_count = methods.len();
        let method_ids: FxHashMap<&str, usize> = methods
            .keys()
            .enumerate()
            .map(|(i, k)| (k.as_str(), i))
            .collect(); // FxHashMap with capacity inferred by collect

        let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); node_count];
        let mut features: Vec<[i32; 13]> = Vec::with_capacity(node_count);

        for (key, method) in &methods {
            let i = method_ids[key.as_str()];
            let (feats, internal_calls) = extract_method_features(method, pkg);
            for callee_key in &internal_calls {
                if let Some(&j) = method_ids.get(callee_key.as_str()) {
                    adjacency[i].push(j);
                }
            }
            features.push(feats);
        }

        let mut in_deg = vec![0i32; node_count];
        for targets in &adjacency {
            for &tgt in targets {
                in_deg[tgt] += 1;
            }
        }
        for i in 0..node_count {
            features[i][IDX_IN_DEGREE] = in_deg[i];
        }

        graph_data.insert(
            (*pkg).clone(),
            Some(PackageGraph {
                adjacency,
                features,
            }),
        );
    }

    (graph_data, method_counts)
}

fn build_neighborhoods(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut neigh: Vec<Vec<usize>> = vec![Vec::new(); adj.len()];
    for (src, targets) in adj.iter().enumerate() {
        for &tgt in targets {
            if !neigh[src].contains(&tgt) {
                neigh[src].push(tgt);
            }
            if !neigh[tgt].contains(&src) {
                neigh[tgt].push(src);
            }
        }
    }
    neigh
}

fn hash_label_and_neighbors(label: u64, neighbor_labels: &[u64]) -> u64 {
    let mut hasher = FxHasher::default();
    label.hash(&mut hasher);
    for &nl in neighbor_labels {
        nl.hash(&mut hasher);
    }
    hasher.finish()
}

fn hash_features(features: &[i32; 13]) -> u64 {
    let mut hasher = FxHasher::default();
    for v in features {
        v.hash(&mut hasher);
    }
    hasher.finish()
}

fn wl_histograms(adj: &[Vec<usize>], features_x: &[[i32; 13]], n_iter: usize) -> WLSig {
    let neigh = build_neighborhoods(adj);
    let mut labels: Vec<u64> = features_x.iter().map(hash_features).collect();
    let mut new_labels = Vec::with_capacity(labels.len());
    let mut nbr_buf = Vec::new();

    let mut hists: Vec<Histogram> = Vec::with_capacity(n_iter + 1);
    for it in 0..=n_iter {
        let mut hist: Histogram = Histogram::default();
        for &lbl in &labels {
            *hist.entry(lbl).or_insert(0) += 1;
        }
        hists.push(hist);
        if it < n_iter {
            new_labels.clear();
            for (v, &lbl) in labels.iter().enumerate() {
                nbr_buf.clear();
                nbr_buf.extend(neigh[v].iter().map(|&n| labels[n]));
                nbr_buf.sort_unstable();
                new_labels.push(hash_label_and_neighbors(lbl, &nbr_buf));
            }
            std::mem::swap(&mut labels, &mut new_labels);
        }
    }
    WLSig {
        hists,
        final_labels: labels,
        adjacency: adj.to_vec(),
    }
}

fn wl_similarity(hists_a: &[Histogram], hists_b: &[Histogram]) -> f64 {
    let mut cross = 0.0f64;
    let mut self_a = 0.0f64;
    let mut self_b = 0.0f64;

    for (ha, hb) in hists_a.iter().zip(hists_b.iter()) {
        let keys: FxHashSet<&u64> = ha.keys().chain(hb.keys()).collect();
        for &lbl in &keys {
            let ca = *ha.get(lbl).unwrap_or(&0) as f64;
            let cb = *hb.get(lbl).unwrap_or(&0) as f64;
            cross += ca.min(cb);
            self_a += ca;
            self_b += cb;
        }
    }

    let denom = (self_a * self_b).sqrt();
    if denom > 0.0 { cross / denom } else { 0.0 }
}

/// Compare the sorted per-node (label, sorted-neighbor-labels) tuples between
/// two packages.  Returns the fraction of nodes (up to the longer package) that
/// have an identical signature — a finer-grained structural measure than the
/// histogram intersection used by [`wl_similarity`].
fn node_label_consistency(a: &WLSig, b: &WLSig) -> f64 {
    let neigh_a = build_neighborhoods(&a.adjacency);
    let neigh_b = build_neighborhoods(&b.adjacency);

    let mut sigs_a: Vec<(u64, Vec<u64>)> = a
        .final_labels
        .iter()
        .enumerate()
        .map(|(v, &lbl)| {
            let mut nbrs: Vec<u64> =
                neigh_a[v].iter().map(|&n| a.final_labels[n]).collect();
            nbrs.sort_unstable();
            (lbl, nbrs)
        })
        .collect();
    let mut sigs_b: Vec<(u64, Vec<u64>)> = b
        .final_labels
        .iter()
        .enumerate()
        .map(|(v, &lbl)| {
            let mut nbrs: Vec<u64> =
                neigh_b[v].iter().map(|&n| b.final_labels[n]).collect();
            nbrs.sort_unstable();
            (lbl, nbrs)
        })
        .collect();

    sigs_a.sort();
    sigs_b.sort();

    let matches = sigs_a.iter().zip(sigs_b.iter()).filter(|(a, b)| a == b).count();
    let max_len = sigs_a.len().max(sigs_b.len());
    if max_len == 0 {
        1.0
    } else {
        matches as f64 / max_len as f64
    }
}

fn compute_sigs_and_names(
    old_data: &FxHashMap<String, Option<PackageGraph>>,
    new_data: &FxHashMap<String, Option<PackageGraph>>,
    n_iter: usize,
) -> (
    SigsMap,
    SigsMap,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
) {
    let old_sigs: SigsMap = old_data
        .par_iter()
        .filter_map(|(name, data_opt)| {
            data_opt.as_ref().map(|data| {
                (
                    name.clone(),
                    wl_histograms(&data.adjacency, &data.features, n_iter),
                )
            })
        })
        .collect();

    let new_sigs: SigsMap = new_data
        .par_iter()
        .filter_map(|(name, data_opt)| {
            data_opt.as_ref().map(|data| {
                (
                    name.clone(),
                    wl_histograms(&data.adjacency, &data.features, n_iter),
                )
            })
        })
        .collect();

    let old_names: Vec<String> = {
        let mut names: Vec<&String> = old_sigs.keys().collect();
        names.sort();
        names.into_iter().cloned().collect()
    };
    let new_names: Vec<String> = {
        let mut names: Vec<&String> = new_sigs.keys().collect();
        names.sort();
        names.into_iter().cloned().collect()
    };

    let old_no_graph: Vec<String> = {
        let mut names: Vec<&String> = old_data.keys().filter(|k| old_data[*k].is_none()).collect();
        names.sort();
        names.into_iter().cloned().collect()
    };
    let new_no_graph: Vec<String> = {
        let mut names: Vec<&String> = new_data.keys().filter(|k| new_data[*k].is_none()).collect();
        names.sort();
        names.into_iter().cloned().collect()
    };

    (
        old_sigs,
        new_sigs,
        old_names,
        new_names,
        old_no_graph,
        new_no_graph,
    )
}

/// Greedy bipartite matching between old and new packages based on WL
/// histogram similarity.  Results are labelled `MATCH`, `CHANGED`,
/// `REMOVED`, or `NEW` depending on `match_threshold` and
/// `change_threshold`.
///
/// When `use_node_matching` is true, the scores of matched/changed pairs are
/// additionally penalised by the node-label consistency check *after* the
/// bipartite assignment is made, so the matching decisions are driven purely
/// by the histogram kernel and the consistency check only refines the final
/// score.
pub fn match_packages(
    old: SideData,
    new: SideData,
    match_threshold: f64,
    change_threshold: f64,
    use_node_matching: bool,
) -> Vec<(String, String, f64, String)> {
    let mut results: Vec<(String, String, f64, String)> = Vec::new();
    let mut used_new: FxHashSet<usize> = FxHashSet::default();
    let mut old_best: Vec<(usize, i32, f64)> = old
        .names
        .par_iter()
        .enumerate()
        .map(|(i, on)| {
            let sig_a = &old.sigs[on];
            let mut best_j = -1i32;
            let mut best_s = 0.0f64;
            for (j, nn) in new.names.iter().enumerate() {
                let sig_b = &new.sigs[nn];
                let s = wl_similarity(&sig_a.hists, &sig_b.hists);
                if s > best_s {
                    best_s = s;
                    best_j = j as i32;
                }
            }
            (i, best_j, best_s)
        })
        .collect();

    old_best.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());

    for &(i, best_j, best_s) in &old_best {
        if best_j >= 0 && !used_new.contains(&(best_j as usize)) && best_s >= change_threshold {
            used_new.insert(best_j as usize);
            let nn = new.names[best_j as usize].clone();
            let status = if best_s >= match_threshold {
                "MATCH"
            } else {
                "CHANGED"
            };
            results.push((old.names[i].clone(), nn, best_s, status.to_string()));
        } else {
            results.push((
                old.names[i].clone(),
                "---".to_string(),
                0.0,
                "REMOVED".to_string(),
            ));
        }
    }

    for (j, nn) in new.names.iter().enumerate() {
        if !used_new.contains(&j) {
            results.push(("---".to_string(), nn.clone(), 0.0, "NEW".to_string()));
        }
    }

    for name in old.no_graph {
        if !results.iter().any(|r| &r.0 == name) {
            results.push((name.clone(), "---".to_string(), 0.0, "REMOVED".to_string()));
        }
    }
    for name in new.no_graph {
        if !results.iter().any(|r| &r.1 == name) {
            results.push(("---".to_string(), name.clone(), 0.0, "NEW".to_string()));
        }
    }

    if use_node_matching {
        for (old_name, new_name, score, status) in &mut results {
            if *status == "MATCH" || *status == "CHANGED" {
                if let (Some(sig_a), Some(sig_b)) =
                    (old.sigs.get(old_name), new.sigs.get(new_name))
                {
                    *score *= node_label_consistency(sig_a, sig_b);
                    if *score < change_threshold {
                        *status = "REMOVED".to_string();
                    } else if *score < match_threshold {
                        *status = "CHANGED".to_string();
                    }
                }
            }
        }
    }

    results
}

/// High-level entry point: build package graphs for both APKs, run WL
/// matching, and return a `MatchResult` with similarity scores.
pub fn run_match(
    old_classes: &[SmaliClass],
    new_classes: &[SmaliClass],
    match_threshold: f64,
    change_threshold: f64,
    wl_iterations: usize,
    use_node_matching: bool,
) -> MatchResult {
    let (old_data, old_method_counts) = build_package_graphs(old_classes);
    let (new_data, new_method_counts) = build_package_graphs(new_classes);
    let (old_sigs, new_sigs, old_names, new_names, old_no_graph, new_no_graph) =
        compute_sigs_and_names(&old_data, &new_data, wl_iterations);
    let results = match_packages(
        SideData {
            sigs: &old_sigs,
            names: &old_names,
            no_graph: &old_no_graph,
        },
        SideData {
            sigs: &new_sigs,
            names: &new_names,
            no_graph: &new_no_graph,
        },
        match_threshold,
        change_threshold,
        use_node_matching,
    );
    MatchResult {
        results,
        old_pkg_methods: old_method_counts,
        new_pkg_methods: new_method_counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smali::smali_ops::{Label, MethodRef, SmaliRegister};
    use smali::types::MethodSignature;

    #[test]
    fn test_get_package_name_standard() {
        assert_eq!(
            get_package_name("Lcom/example/MyClass;"),
            Some("com/example".to_string())
        );
    }

    #[test]
    fn test_get_package_name_default_package() {
        assert_eq!(get_package_name("LMyClass;"), Some(String::new()));
    }

    #[test]
    fn test_get_package_name_invalid() {
        assert_eq!(get_package_name("not-jni"), None);
    }

    #[test]
    fn test_pkg_display_normal() {
        assert_eq!(pkg_display("com/example"), "com.example");
    }

    #[test]
    fn test_pkg_display_empty() {
        assert_eq!(pkg_display(""), "(default)");
    }

    #[test]
    fn test_categorize_external_android() {
        assert_eq!(categorize_external("Landroid/app/Activity;"), "android");
    }

    #[test]
    fn test_categorize_external_androidx() {
        assert_eq!(
            categorize_external("Landroidx/core/app/Activity;"),
            "androidx"
        );
    }

    #[test]
    fn test_categorize_external_java() {
        assert_eq!(categorize_external("Ljava/lang/String;"), "java");
        assert_eq!(categorize_external("Ljavax/net/ssl/SSLSocket;"), "java");
    }

    #[test]
    fn test_categorize_external_kotlin() {
        assert_eq!(
            categorize_external("Lkotlin/jvm/internal/Intrinsics;"),
            "kotlin"
        );
        assert_eq!(
            categorize_external("Lkotlinx/coroutines/CoroutineScope;"),
            "kotlin"
        );
    }

    #[test]
    fn test_categorize_external_other() {
        assert_eq!(categorize_external("Lcom/example/MyClass;"), "other");
    }

    #[test]
    fn test_is_branch_op_if_eq() {
        assert!(is_branch_op(&DexOp::IfEq {
            reg1: SmaliRegister::Local(0),
            reg2: SmaliRegister::Local(1),
            offset: Label("L1".to_string()),
        }));
    }

    #[test]
    fn test_is_branch_op_return_void() {
        assert!(!is_branch_op(&DexOp::ReturnVoid));
    }

    #[test]
    fn test_is_branch_op_goto() {
        assert!(is_branch_op(&DexOp::Goto {
            offset: Label("L1".to_string()),
        }));
    }

    #[test]
    fn test_is_branch_op_switch() {
        assert!(is_branch_op(&DexOp::PackedSwitch {
            reg: SmaliRegister::Local(0),
            offset: Label("L1".to_string()),
        }));
        assert!(is_branch_op(&DexOp::SparseSwitch {
            reg: SmaliRegister::Local(0),
            offset: Label("L1".to_string()),
        }));
    }

    #[test]
    fn test_get_method_key() {
        let m = SmaliMethod {
            name: "foo".to_string(),
            modifiers: vec![],
            constructor: false,
            signature: MethodSignature::from_jni("()V"),
            locals: 0,
            registers: None,
            params: vec![],
            annotations: vec![],
            ops: vec![],
        };
        let key = get_method_key("Lcom/example/MyClass;", &m);
        assert_eq!(key, "Lcom/example/MyClass;->foo()V");
    }

    #[test]
    fn test_hash_features_stable() {
        let f1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        let f2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        assert_eq!(hash_features(&f1), hash_features(&f2));
    }

    #[test]
    fn test_hash_features_different() {
        let f1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        let f2 = [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        assert_ne!(hash_features(&f1), hash_features(&f2));
    }

    #[test]
    fn test_hash_label_and_neighbors_stable() {
        let h1 = hash_label_and_neighbors(42, &[1, 2, 3]);
        let h2 = hash_label_and_neighbors(42, &[1, 2, 3]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_label_and_neighbors_different_label() {
        let h1 = hash_label_and_neighbors(42, &[1, 2, 3]);
        let h2 = hash_label_and_neighbors(99, &[1, 2, 3]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_label_and_neighbors_different_neighbors() {
        let h1 = hash_label_and_neighbors(42, &[1, 2, 3]);
        let h2 = hash_label_and_neighbors(42, &[4, 5, 6]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_wl_similarity_identical() {
        let hist_a: Vec<Histogram> = vec![
            [(1, 2), (2, 3)].into_iter().collect(),
            [(3, 1)].into_iter().collect(),
        ];
        let hist_b = hist_a.clone();
        let sim = wl_similarity(&hist_a, &hist_b);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_wl_similarity_orthogonal() {
        let hist_a: Vec<Histogram> = vec![[(1, 2)].into_iter().collect()];
        let hist_b: Vec<Histogram> = vec![[(2, 2)].into_iter().collect()];
        let sim = wl_similarity(&hist_a, &hist_b);
        assert!((sim - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_wl_similarity_partial() {
        let hist_a: Vec<Histogram> = vec![[(1, 2), (2, 2)].into_iter().collect()];
        let hist_b: Vec<Histogram> = vec![[(1, 1), (2, 3)].into_iter().collect()];
        let sim = wl_similarity(&hist_a, &hist_b);
        let expected = 3.0 / (4.0f64 * 4.0f64).sqrt(); // min(2,1) + min(2,3) = 3, self_a=4, self_b=4
        assert!((sim - expected).abs() < 1e-9);
    }

    #[test]
    fn test_extract_method_features_no_ops() {
        let method = SmaliMethod {
            name: "foo".to_string(),
            modifiers: vec![],
            constructor: false,
            signature: MethodSignature::from_jni("()V"),
            locals: 0,
            registers: None,
            params: vec![],
            annotations: vec![],
            ops: vec![],
        };
        let (features, calls) = extract_method_features(&method, "com/example");
        assert_eq!(features[IDX_NUM_PARAMS], 0);
        assert_eq!(features[IDX_NUM_INSTRUCTIONS], 0);
        assert_eq!(features[IDX_OUT_DEGREE], 0);
        assert!(calls.is_empty());
    }

    #[test]
    fn test_extract_method_features_with_invoke() {
        let method = SmaliMethod {
            name: "bar".to_string(),
            modifiers: vec![],
            constructor: false,
            signature: MethodSignature::from_jni("()V"),
            locals: 0,
            registers: None,
            params: vec![],
            annotations: vec![],
            ops: vec![SmaliOp::Op(DexOp::InvokeVirtual {
                registers: vec![],
                method: MethodRef {
                    class: "Landroid/app/Activity;".to_string(),
                    name: "onCreate".to_string(),
                    descriptor: "(Landroid/os/Bundle;)V".to_string(),
                },
            })],
        };
        let (features, calls) = extract_method_features(&method, "com/example");
        assert_eq!(features[IDX_INVOKE_VIRTUAL], 1);
        assert_eq!(features[IDX_NUM_INSTRUCTIONS], 1);
        assert_eq!(features[IDX_OUT_DEGREE], 1);
        assert_eq!(features[IDX_EXT_ANDROID], 1);
        assert!(calls.is_empty()); // not internal to com/example
    }

    #[test]
    fn test_extract_method_features_internal_call() {
        let method = SmaliMethod {
            name: "callInternal".to_string(),
            modifiers: vec![],
            constructor: false,
            signature: MethodSignature::from_jni("()V"),
            locals: 0,
            registers: None,
            params: vec![],
            annotations: vec![],
            ops: vec![SmaliOp::Op(DexOp::InvokeStatic {
                registers: vec![],
                method: MethodRef {
                    class: "Lcom/example/MyClass;".to_string(),
                    name: "internalMethod".to_string(),
                    descriptor: "()V".to_string(),
                },
            })],
        };
        let pkg = "com/example";
        let (features, calls) = extract_method_features(&method, pkg);
        assert_eq!(features[IDX_INVOKE_STATIC], 1);
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("internalMethod"));
    }

    #[test]
    fn test_extract_method_features_branch() {
        let method = SmaliMethod {
            name: "brancher".to_string(),
            modifiers: vec![],
            constructor: false,
            signature: MethodSignature::from_jni("()V"),
            locals: 0,
            registers: None,
            params: vec![],
            annotations: vec![],
            ops: vec![SmaliOp::Op(DexOp::IfEq {
                reg1: SmaliRegister::Local(0),
                reg2: SmaliRegister::Local(1),
                offset: Label("L1".to_string()),
            })],
        };
        let (features, _) = extract_method_features(&method, "com/example");
        assert_eq!(features[IDX_HAS_BRANCHES], 1);
    }

    #[test]
    fn test_build_neighborhoods_simple() {
        let adj = vec![vec![1], vec![0, 2], vec![1]];
        let neigh = build_neighborhoods(&adj);
        assert!(neigh[0].contains(&1));
        assert!(neigh[2].contains(&1));
        assert!(neigh[1].contains(&0));
        assert!(neigh[1].contains(&2));
    }

    #[test]
    fn test_build_neighborhoods_no_edges() {
        let adj = vec![vec![], vec![], vec![]];
        let neigh = build_neighborhoods(&adj);
        for n in &neigh {
            assert!(n.is_empty());
        }
    }

    #[test]
    fn test_wl_histograms_single_node() {
        let adj = vec![vec![]];
        let features = [[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]];
        let sig = wl_histograms(&adj, &features, 2);
        assert_eq!(sig.hists.len(), 3); // 0, 1, 2 iterations
        for hist in &sig.hists {
            assert_eq!(hist.len(), 1); // single node, single label
        }
    }

    #[test]
    fn test_wl_histograms_two_nodes() {
        let adj = vec![vec![1], vec![0]];
        let features = [
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        let sig = wl_histograms(&adj, &features, 1);
        assert_eq!(sig.hists.len(), 2);
        // initial hist should have 2 distinct labels
        assert_eq!(sig.hists[0].len(), 2);
    }

    #[test]
    fn test_match_packages_simple() {
        let old_sigs: SigsMap = [(
            "pkgA".to_string(),
            WLSig {
                hists: vec![[(1, 2)].into_iter().collect()],
                final_labels: vec![],
                adjacency: vec![],
            },
        )]
        .into_iter()
        .collect();
        let new_sigs: SigsMap = [(
            "pkgA".to_string(),
            WLSig {
                hists: vec![[(1, 2)].into_iter().collect()],
                final_labels: vec![],
                adjacency: vec![],
            },
        )]
        .into_iter()
        .collect();
        let old_names = vec!["pkgA".to_string()];
        let new_names = vec!["pkgA".to_string()];
        let results = match_packages(
            SideData {
                sigs: &old_sigs,
                names: &old_names,
                no_graph: &[],
            },
            SideData {
                sigs: &new_sigs,
                names: &new_names,
                no_graph: &[],
            },
            0.8,
            0.0,
            false,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "pkgA");
        assert_eq!(results[0].1, "pkgA");
        assert_eq!(results[0].3, "MATCH");
    }

    #[test]
    fn test_match_packages_removed() {
        let old_sigs: SigsMap = [(
            "pkgOld".to_string(),
            WLSig {
                hists: vec![[(1, 2)].into_iter().collect()],
                final_labels: vec![],
                adjacency: vec![],
            },
        )]
        .into_iter()
        .collect();
        let new_sigs: SigsMap = FxHashMap::default();
        let old_names = vec!["pkgOld".to_string()];
        let new_names: Vec<String> = vec![];
        let results = match_packages(
            SideData {
                sigs: &old_sigs,
                names: &old_names,
                no_graph: &[],
            },
            SideData {
                sigs: &new_sigs,
                names: &new_names,
                no_graph: &[],
            },
            0.8,
            0.0,
            false,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].3, "REMOVED");
    }

    #[test]
    fn test_match_packages_new() {
        let old_sigs: SigsMap = FxHashMap::default();
        let new_sigs: SigsMap = [(
            "pkgNew".to_string(),
            WLSig {
                hists: vec![[(1, 2)].into_iter().collect()],
                final_labels: vec![],
                adjacency: vec![],
            },
        )]
        .into_iter()
        .collect();
        let old_names: Vec<String> = vec![];
        let new_names = vec!["pkgNew".to_string()];
        let results = match_packages(
            SideData {
                sigs: &old_sigs,
                names: &old_names,
                no_graph: &[],
            },
            SideData {
                sigs: &new_sigs,
                names: &new_names,
                no_graph: &[],
            },
            0.8,
            0.0,
            false,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].3, "NEW");
    }

    #[test]
    fn test_match_packages_no_graph() {
        let results = match_packages(
            SideData {
                sigs: &FxHashMap::default(),
                names: &[],
                no_graph: &["pkgEmpty".to_string()],
            },
            SideData {
                sigs: &FxHashMap::default(),
                names: &[],
                no_graph: &[],
            },
            0.8,
            0.0,
            false,
        );
        assert!(
            results
                .iter()
                .any(|r| r.0 == "pkgEmpty" && r.3 == "REMOVED")
        );
    }
}
