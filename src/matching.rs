use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use smali::smali_ops::DexOp;
use smali::types::{SmaliClass, SmaliMethod, SmaliOp};

pub type Histogram = FxHashMap<u64, usize>;
type SigsMap = FxHashMap<String, Vec<Histogram>>;

#[derive(Clone)]
pub struct PackageGraph {
    pub adjacency: Vec<Vec<usize>>,
    pub features: Vec<[i32; 13]>,
}

pub struct MatchResult {
    pub results: Vec<(String, String, f64, String)>,
    pub old_pkg_methods: HashMap<String, usize>,
    pub new_pkg_methods: HashMap<String, usize>,
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

fn extract_method_features(
    method: &SmaliMethod,
    package_name: &str,
) -> ([i32; 13], Vec<String>) {
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
            DexOp::InvokeVirtual { method, .. }
            | DexOp::InvokeVirtualRange { method, .. } => ("virtual", Some(method)),
            DexOp::InvokeSuper { method, .. } | DexOp::InvokeSuperRange { method, .. } => {
                ("super", Some(method))
            }
            DexOp::InvokeDirect { method, .. } | DexOp::InvokeDirectRange { method, .. } => {
                ("direct", Some(method))
            }
            DexOp::InvokeStatic { method, .. } | DexOp::InvokeStaticRange { method, .. } => {
                ("static", Some(method))
            }
            DexOp::InvokeInterface { method, .. }
            | DexOp::InvokeInterfaceRange { method, .. } => ("interface", Some(method)),
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

pub fn build_package_graphs(
    classes: &[SmaliClass],
) -> (
    HashMap<String, Option<PackageGraph>>,
    HashMap<String, usize>,
) {
    let mut pkgs: HashMap<String, Vec<&SmaliClass>> = HashMap::new();
    for c in classes {
        let jni = c.name.as_jni_type();
        if let Some(pkg) = get_package_name(&jni) {
            pkgs.entry(pkg).or_default().push(c);
        }
    }

    let mut method_counts: HashMap<String, usize> = HashMap::new();
    let mut graph_data: HashMap<String, Option<PackageGraph>> = HashMap::new();
    for (pkg, cls_list) in &pkgs {
        let total_methods: usize = cls_list.iter().map(|c| c.methods.len()).sum();
        method_counts.insert((*pkg).clone(), total_methods);

        let mut methods: HashMap<String, &SmaliMethod> = HashMap::new();
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
            .collect();

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
            Some(PackageGraph { adjacency, features }),
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
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut hasher);
    for &nl in neighbor_labels {
        nl.hash(&mut hasher);
    }
    hasher.finish()
}

fn hash_features(features: &[i32; 13]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for v in features {
        v.hash(&mut hasher);
    }
    hasher.finish()
}

fn wl_histograms(
    adj: &[Vec<usize>],
    features_x: &[[i32; 13]],
    n_iter: usize,
) -> Vec<Histogram> {
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
    hists
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
    if denom > 0.0 {
        cross / denom
    } else {
        0.0
    }
}

fn compute_sigs_and_names(
    old_data: &HashMap<String, Option<PackageGraph>>,
    new_data: &HashMap<String, Option<PackageGraph>>,
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
            data_opt
                .as_ref()
                .map(|data| (name.clone(), wl_histograms(&data.adjacency, &data.features, n_iter)))
        })
        .collect();

    let new_sigs: SigsMap = new_data
        .par_iter()
        .filter_map(|(name, data_opt)| {
            data_opt
                .as_ref()
                .map(|data| (name.clone(), wl_histograms(&data.adjacency, &data.features, n_iter)))
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

    (old_sigs, new_sigs, old_names, new_names, old_no_graph, new_no_graph)
}

pub fn match_packages(
    old_sigs: &SigsMap,
    new_sigs: &SigsMap,
    old_names: &[String],
    new_names: &[String],
    match_threshold: f64,
    change_threshold: f64,
    old_no_graph: &[String],
    new_no_graph: &[String],
) -> Vec<(String, String, f64, String)> {
    let mut results: Vec<(String, String, f64, String)> = Vec::new();
    let mut used_new: FxHashSet<usize> = FxHashSet::default();

    let mut old_best: Vec<(usize, i32, f64)> = old_names
        .par_iter()
        .enumerate()
        .map(|(i, on)| {
            let hi_a = &old_sigs[on];
            let mut best_j = -1i32;
            let mut best_s = 0.0f64;
            for (j, nn) in new_names.iter().enumerate() {
                let s = wl_similarity(hi_a, &new_sigs[nn]);
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
        if best_j >= 0
            && !used_new.contains(&(best_j as usize))
            && best_s >= change_threshold
        {
            used_new.insert(best_j as usize);
            let nn = new_names[best_j as usize].clone();
            let status = if best_s >= match_threshold {
                "MATCH"
            } else {
                "CHANGED"
            };
            results.push((old_names[i].clone(), nn, best_s, status.to_string()));
        } else {
            results.push((
                old_names[i].clone(),
                "---".to_string(),
                0.0,
                "REMOVED".to_string(),
            ));
        }
    }

    for (j, nn) in new_names.iter().enumerate() {
        if !used_new.contains(&j) {
            results.push(("---".to_string(), nn.clone(), 0.0, "NEW".to_string()));
        }
    }

    for name in old_no_graph {
        if !results.iter().any(|r| &r.0 == name) {
            results.push((
                name.clone(),
                "---".to_string(),
                0.0,
                "REMOVED".to_string(),
            ));
        }
    }
    for name in new_no_graph {
        if !results.iter().any(|r| &r.1 == name) {
            results.push((
                "---".to_string(),
                name.clone(),
                0.0,
                "NEW".to_string(),
            ));
        }
    }

    results
}

pub fn run_match(
    old_classes: &[SmaliClass],
    new_classes: &[SmaliClass],
    match_threshold: f64,
    change_threshold: f64,
    wl_iterations: usize,
) -> MatchResult {
    let (old_data, old_method_counts) = build_package_graphs(old_classes);
    let (new_data, new_method_counts) = build_package_graphs(new_classes);
    let (old_sigs, new_sigs, old_names, new_names, old_no_graph, new_no_graph) =
        compute_sigs_and_names(&old_data, &new_data, wl_iterations);
    let results = match_packages(
        &old_sigs,
        &new_sigs,
        &old_names,
        &new_names,
        match_threshold,
        change_threshold,
        &old_no_graph,
        &new_no_graph,
    );
    MatchResult {
        results,
        old_pkg_methods: old_method_counts,
        new_pkg_methods: new_method_counts,
    }
}
