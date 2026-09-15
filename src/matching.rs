//! Weisfeiler-Lehman graph kernel matching across packages in two APKs.
//!
//! Builds a call-graph per package, extracts a 19-dimensional feature
//! vector per method, runs WL refinement to produce multi-level histogram
//! signatures, then performs greedy bipartite matching between packages.

use std::hash::{Hash, Hasher};

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use smali::smali_ops::DexOp;
use smali::types::{SmaliClass, SmaliMethod, SmaliOp, TypeSignature};

/// A count of how many times each WL label appears at a given iteration.
pub type Histogram = FxHashMap<u64, usize>;

/// A single matching result entry: (old_package, new_package, similarity_score, status).
/// Status is one of `MATCH`, `CHANGED`, `REMOVED`, or `NEW`.
pub type MatchEntry = (String, String, f64, String);

/// Parameters that control the matching algorithm.
pub struct MatchParams {
    pub match_threshold: f64,
    pub change_threshold: f64,
    pub wl_iterations: usize,
    pub use_node_matching: bool,
    pub api_weight: f64,
    pub hier_weight: f64,
    pub string_weight: f64,
    pub excluded_features: Vec<Feature>,
}

/// A scoring feature that can be excluded from the combined match score.
/// Coarse variants drop whole similarity components from the score; dimension
/// variants mask a single slot of the 19-dimensional per-method feature
/// vector before WL label hashing; `api_*` variants drop a category of
/// external calls from the API fingerprint (and mask its `ext_*` dimension).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum Feature {
    /// Weisfeiler-Lehman graph-histogram similarity.
    Wl,
    /// API-call fingerprint Jaccard similarity.
    Api,
    /// String-constant content fingerprint Jaccard similarity.
    String,
    /// Hierarchical ancestor-consistency boost.
    Hier,
    /// WL feature dimension: per-node in-degree.
    InDegree,
    /// WL feature dimension: per-node out-degree.
    OutDegree,
    /// WL feature dimension: count of calls to android/androidx classes.
    ExtAndroid,
    /// WL feature dimension: count of calls to java/javax classes.
    ExtJava,
    /// WL feature dimension: count of calls to kotlin/kotlinx classes.
    ExtKotlin,
    /// WL feature dimension: count of calls to other external classes.
    ExtOther,
    /// WL feature dimension: count of invoke-virtual/super ops.
    InvokeVirtual,
    /// WL feature dimension: count of invoke-static ops.
    InvokeStatic,
    /// WL feature dimension: count of invoke-direct ops.
    InvokeDirect,
    /// WL feature dimension: count of invoke-interface ops.
    InvokeInterface,
    /// WL feature dimension: number of parameters.
    NumParams,
    /// WL feature dimension: number of instructions.
    NumInstructions,
    /// WL feature dimension: whether the method has branch/switch ops.
    HasBranches,
    /// WL feature dimension: number of const-string ops.
    StringConsts,
    /// WL feature dimension: number of field access ops.
    FieldAccess,
    /// WL feature dimension: number of try/catch handlers.
    TryCatch,
    /// WL feature dimension: register (or local) count.
    RegisterCount,
    /// WL feature dimension: whether the method is a constructor.
    IsConstructor,
    /// WL feature dimension: return-type category.
    ReturnType,
    /// API fingerprint category: android framework calls.
    ApiAndroid,
    /// API fingerprint category: androidx/androidx-compat calls.
    ApiAndroidx,
    /// API fingerprint category: java/javax calls.
    ApiJava,
    /// API fingerprint category: kotlin/kotlinx calls.
    ApiKotlin,
    /// API fingerprint category: all other external calls.
    ApiOther,
}

/// Bundles the WL histograms, per-node final labels, and adjacency of a
/// single package, so the matching layer can optionally run a node-label
/// consistency check in addition to histogram intersection.
pub struct WLSig {
    pub hists: Vec<Histogram>,
    pub final_labels: Vec<u64>,
    pub adjacency: Vec<Vec<usize>>,
}

type SigsMap = FxHashMap<String, WLSig>;

/// API-call fingerprint for a single package: the set of (class, method_name)
/// pairs this package calls externally. These survive obfuscation because
/// framework/library class names are never renamed.
#[derive(Clone, Default)]
pub struct ApiFingerprint {
    pub api_calls: FxHashSet<(String, String)>,
}

type ApiFingerprints = FxHashMap<String, ApiFingerprint>;

/// String-constant fingerprint for a single package: the set of unique
/// string literal values used by methods in this package.
/// String values survive R8 obfuscation unchanged, making this a stable
/// signal for matching packages across obfuscated and unobfuscated APKs.
#[derive(Clone, Default)]
pub struct StringFingerprint {
    pub strings: FxHashSet<String>,
}

type StringFingerprints = FxHashMap<String, StringFingerprint>;

pub struct SideData<'a> {
    pub sigs: &'a SigsMap,
    pub names: &'a [String],
    pub no_graph: &'a [String],
    pub api_fps: &'a ApiFingerprints,
    pub string_fps: &'a StringFingerprints,
}

/// A directed call graph for a single package.
/// Each node corresponds to a method; edges represent internal calls.
#[derive(Clone)]
pub struct PackageGraph {
    /// Adjacency list: for each node, the indices of methods it calls.
    pub adjacency: Vec<Vec<usize>>,
    /// 19-element feature vectors for each method node.
    pub features: Vec<[i32; 19]>,
}

/// The output of a matching run.
pub struct MatchResult {
    /// Each entry: `(old_package, new_package, similarity_score, status)`.
    /// Status is one of `MATCH`, `CHANGED`, `REMOVED`, or `NEW`.
    pub results: Vec<MatchEntry>,
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
const IDX_STRING_CONSTS: usize = 13;
const IDX_FIELD_ACCESS: usize = 14;
const IDX_TRY_CATCH: usize = 15;
const IDX_REGISTER_COUNT: usize = 16;
const IDX_IS_CONSTRUCTOR: usize = 17;
const IDX_RETURN_TYPE: usize = 18;

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

/// Build a per-dimension mask describing which of the 19 WL feature
/// dimensions are excluded. Both explicit dimension exclusions and `api_*`
/// category exclusions set bits, the latter because the `ext_*` counters are
/// derived from those same external-call categories. A `true` slot means that
/// dimension is masked (zeroed) before WL label hashing.
fn feature_dim_mask(excluded: &[Feature]) -> [bool; 19] {
    let mut mask = [false; 19];
    for f in excluded {
        let idx: Option<usize> = match f {
            Feature::InDegree => Some(IDX_IN_DEGREE),
            Feature::OutDegree => Some(IDX_OUT_DEGREE),
            Feature::ExtAndroid | Feature::ApiAndroid | Feature::ApiAndroidx => {
                Some(IDX_EXT_ANDROID)
            }
            Feature::ExtJava | Feature::ApiJava => Some(IDX_EXT_JAVA),
            Feature::ExtKotlin | Feature::ApiKotlin => Some(IDX_EXT_KOTLIN),
            Feature::ExtOther | Feature::ApiOther => Some(IDX_EXT_OTHER),
            Feature::InvokeVirtual => Some(IDX_INVOKE_VIRTUAL),
            Feature::InvokeStatic => Some(IDX_INVOKE_STATIC),
            Feature::InvokeDirect => Some(IDX_INVOKE_DIRECT),
            Feature::InvokeInterface => Some(IDX_INVOKE_INTERFACE),
            Feature::NumParams => Some(IDX_NUM_PARAMS),
            Feature::NumInstructions => Some(IDX_NUM_INSTRUCTIONS),
            Feature::HasBranches => Some(IDX_HAS_BRANCHES),
            Feature::StringConsts => Some(IDX_STRING_CONSTS),
            Feature::FieldAccess => Some(IDX_FIELD_ACCESS),
            Feature::TryCatch => Some(IDX_TRY_CATCH),
            Feature::RegisterCount => Some(IDX_REGISTER_COUNT),
            Feature::IsConstructor => Some(IDX_IS_CONSTRUCTOR),
            Feature::ReturnType => Some(IDX_RETURN_TYPE),
            _ => None,
        };
        if let Some(i) = idx {
            mask[i] = true;
        }
    }
    mask
}

/// Check whether external calls to `jni_class` are excluded by any `api_*`
/// feature in the exclusion list.
fn is_api_category_excluded(excluded: &[Feature], jni_class: &str) -> bool {
    let cat = categorize_external(jni_class);
    excluded.iter().any(|f| match f {
        Feature::ApiAndroid => cat == "android",
        Feature::ApiAndroidx => cat == "androidx",
        Feature::ApiJava => cat == "java",
        Feature::ApiKotlin => cat == "kotlin",
        Feature::ApiOther => cat == "other",
        _ => false,
    })
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
type MethodFeatures = ([i32; 19], Vec<String>, Vec<(String, String)>, Vec<String>);
fn extract_method_features(method: &SmaliMethod, package_name: &str) -> MethodFeatures {
    let mut features = [0i32; 19];

    features[IDX_NUM_PARAMS] = method.params.len() as i32;

    let mut internal_calls: Vec<String> = Vec::new();
    let mut api_calls: Vec<(String, String)> = Vec::new();
    let mut method_strings: Vec<String> = Vec::new();
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
    let mut string_consts = 0i32;
    let mut field_access = 0i32;

    for sop in &method.ops {
        let SmaliOp::Op(dop) = sop else {
            if matches!(sop, SmaliOp::Catch(_)) {
                features[IDX_TRY_CATCH] += 1;
            }
            continue;
        };
        num_instructions += 1;

        if is_branch_op(dop) {
            has_branches = 1;
        }

        match dop {
            DexOp::ConstString { value, .. } | DexOp::ConstStringJumbo { value, .. } => {
                string_consts += 1;
                method_strings.push(value.clone());
            }
            _ => {}
        }

        if matches!(
            dop,
            DexOp::IGet { .. }
                | DexOp::IGetWide { .. }
                | DexOp::IGetObject { .. }
                | DexOp::IGetBoolean { .. }
                | DexOp::IGetByte { .. }
                | DexOp::IGetChar { .. }
                | DexOp::IGetShort { .. }
                | DexOp::IPut { .. }
                | DexOp::IPutWide { .. }
                | DexOp::IPutObject { .. }
                | DexOp::IPutBoolean { .. }
                | DexOp::IPutByte { .. }
                | DexOp::IPutChar { .. }
                | DexOp::IPutShort { .. }
                | DexOp::SGet { .. }
                | DexOp::SGetWide { .. }
                | DexOp::SGetObject { .. }
                | DexOp::SGetBoolean { .. }
                | DexOp::SGetByte { .. }
                | DexOp::SGetChar { .. }
                | DexOp::SGetShort { .. }
                | DexOp::SPut { .. }
                | DexOp::SPutWide { .. }
                | DexOp::SPutObject { .. }
                | DexOp::SPutBoolean { .. }
                | DexOp::SPutByte { .. }
                | DexOp::SPutChar { .. }
                | DexOp::SPutShort { .. }
        ) {
            field_access += 1;
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
                // Collect external API calls: (class, method_name)
                api_calls.push((mref.class.clone(), mref.name.clone()));
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
    features[IDX_STRING_CONSTS] = string_consts;
    features[IDX_FIELD_ACCESS] = field_access;
    features[IDX_REGISTER_COUNT] = method.registers.unwrap_or(method.locals) as i32;
    features[IDX_IS_CONSTRUCTOR] = if method.constructor { 1 } else { 0 };
    features[IDX_RETURN_TYPE] = match &method.signature.result {
        t if t == &TypeSignature::Void => 0,
        t if is_primitive_type(t) => 1,
        _ => 2,
    };

    (features, internal_calls, api_calls, method_strings)
}

fn is_primitive_type(ts: &TypeSignature) -> bool {
    matches!(
        ts,
        TypeSignature::Bool
            | TypeSignature::Byte
            | TypeSignature::Char
            | TypeSignature::Short
            | TypeSignature::Int
            | TypeSignature::Long
            | TypeSignature::Float
            | TypeSignature::Double
    )
}

/// Partition a list of `SmaliClass` values by package, build a
/// `PackageGraph` (call graph + feature vectors) for each non-empty
/// package, and return the method counts per package. External API calls
/// whose category is excluded by an `api_*` item in `excluded` are dropped
/// from the API fingerprints.
pub fn build_package_graphs(
    classes: &[SmaliClass],
    excluded: &[Feature],
) -> (
    FxHashMap<String, Option<PackageGraph>>,
    FxHashMap<String, usize>,
    ApiFingerprints,
    StringFingerprints,
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
    let mut api_fingerprints: ApiFingerprints = FxHashMap::default();
    let mut string_fingerprints: StringFingerprints = FxHashMap::default();
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
            api_fingerprints.insert((*pkg).clone(), ApiFingerprint::default());
            string_fingerprints.insert((*pkg).clone(), StringFingerprint::default());
            continue;
        }

        let node_count = methods.len();
        let method_ids: FxHashMap<&str, usize> = methods
            .keys()
            .enumerate()
            .map(|(i, k)| (k.as_str(), i))
            .collect();

        let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); node_count];
        let mut features: Vec<[i32; 19]> = Vec::with_capacity(node_count);
        let mut pkg_api_calls: FxHashSet<(String, String)> = FxHashSet::default();
        let mut pkg_strings: FxHashSet<String> = FxHashSet::default();

        for (key, method) in &methods {
            let i = method_ids[key.as_str()];
            let (feats, internal_calls, api_calls, method_strings) =
                extract_method_features(method, pkg);
            for callee_key in &internal_calls {
                if let Some(&j) = method_ids.get(callee_key.as_str()) {
                    adjacency[i].push(j);
                }
            }
            features.push(feats);
            for (class, method_name) in api_calls {
                if !is_api_category_excluded(excluded, &class) {
                    pkg_api_calls.insert((class, method_name));
                }
            }
            for s in method_strings {
                pkg_strings.insert(s);
            }
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
        api_fingerprints.insert(
            (*pkg).clone(),
            ApiFingerprint {
                api_calls: pkg_api_calls,
            },
        );
        string_fingerprints.insert(
            (*pkg).clone(),
            StringFingerprint {
                strings: pkg_strings,
            },
        );
    }

    (
        graph_data,
        method_counts,
        api_fingerprints,
        string_fingerprints,
    )
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

fn hash_features(features: &[i32; 19]) -> u64 {
    let mut hasher = FxHasher::default();
    for v in features {
        v.hash(&mut hasher);
    }
    hasher.finish()
}

fn wl_histograms(
    adj: &[Vec<usize>],
    features_x: &[[i32; 19]],
    n_iter: usize,
    dim_mask: &[bool; 19],
) -> WLSig {
    let neigh = build_neighborhoods(adj);
    let masked = dim_mask.iter().any(|&m| m);
    let mut labels: Vec<u64> = features_x
        .iter()
        .map(|f| {
            if !masked {
                return hash_features(f);
            }
            let mut c = *f;
            for (i, &m) in dim_mask.iter().enumerate() {
                if m {
                    c[i] = 0;
                }
            }
            hash_features(&c)
        })
        .collect();
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

/// Compute Jaccard similarity between two API-call fingerprints.
/// A score of 1.0 means both packages call exactly the same framework/library APIs;
/// 0.0 means they share no external API calls.
fn api_similarity(a: &ApiFingerprint, b: &ApiFingerprint) -> f64 {
    let intersection = a.api_calls.intersection(&b.api_calls).count();
    let union = a.api_calls.union(&b.api_calls).count();
    if union == 0 {
        // Both packages have no external API calls — they're equivalent in API space
        1.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Compute Jaccard similarity between two string-constant fingerprints.
/// A score of 1.0 means both packages use exactly the same set of string
/// literals; 0.0 means they share no strings.  String values survive R8
/// obfuscation unchanged, making this a strong signal for cross-obfuscation
/// matching.
fn string_similarity(a: &StringFingerprint, b: &StringFingerprint) -> f64 {
    let intersection = a.strings.intersection(&b.strings).count();
    let union = a.strings.union(&b.strings).count();
    if union == 0 {
        1.0
    } else {
        intersection as f64 / union as f64
    }
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
            let mut nbrs: Vec<u64> = neigh_a[v].iter().map(|&n| a.final_labels[n]).collect();
            nbrs.sort_unstable();
            (lbl, nbrs)
        })
        .collect();
    let mut sigs_b: Vec<(u64, Vec<u64>)> = b
        .final_labels
        .iter()
        .enumerate()
        .map(|(v, &lbl)| {
            let mut nbrs: Vec<u64> = neigh_b[v].iter().map(|&n| b.final_labels[n]).collect();
            nbrs.sort_unstable();
            (lbl, nbrs)
        })
        .collect();

    sigs_a.sort();
    sigs_b.sort();

    let matches = sigs_a
        .iter()
        .zip(sigs_b.iter())
        .filter(|(a, b)| a == b)
        .count();
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
    dim_mask: &[bool; 19],
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
                    wl_histograms(&data.adjacency, &data.features, n_iter, dim_mask),
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
                    wl_histograms(&data.adjacency, &data.features, n_iter, dim_mask),
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

/// Compute the effective weights for a matching run. Excluded features are
/// left out of the normalization pool entirely, and the retained weights are
/// scaled so the base components (wl, api, string) sum to 1.0. Returns
/// `(wl_weight, api_weight, string_weight, hier_weight)`.
fn effective_weights(params: &MatchParams) -> (f64, f64, f64, f64) {
    let ex = &params.excluded_features;
    let hier = if ex.contains(&Feature::Hier) {
        0.0
    } else {
        params.hier_weight
    };

    let retained_wl = if ex.contains(&Feature::Wl) {
        0.0
    } else {
        (1.0 - params.api_weight - params.string_weight).max(0.0)
    };
    let retained_api = if ex.contains(&Feature::Api) {
        0.0
    } else {
        params.api_weight
    };
    let retained_string = if ex.contains(&Feature::String) {
        0.0
    } else {
        params.string_weight
    };

    let total = retained_wl + retained_api + retained_string;
    if total <= 0.0 {
        tracing::warn!("All matching features excluded; scores will be zero");
        (0.0, 0.0, 0.0, hier)
    } else {
        (
            retained_wl / total,
            retained_api / total,
            retained_string / total,
            hier,
        )
    }
}

fn compute_scores(
    old: &SideData,
    new: &SideData,
    wl_weight: f64,
    api_weight: f64,
    string_weight: f64,
) -> Vec<(usize, i32, f64)> {
    old.names
        .par_iter()
        .enumerate()
        .map(|(i, on)| {
            let sig_a = &old.sigs[on];
            let fp_a = old.api_fps.get(on);
            let sfp_a = old.string_fps.get(on);
            let mut best_j = -1i32;
            let mut best_s = 0.0f64;
            for (j, nn) in new.names.iter().enumerate() {
                let sig_b = &new.sigs[nn];
                let fp_b = new.api_fps.get(nn);
                let sfp_b = new.string_fps.get(nn);
                let s_wl = wl_similarity(&sig_a.hists, &sig_b.hists);
                let s_api = match (fp_a, fp_b) {
                    (Some(a), Some(b)) => api_similarity(a, b),
                    _ => 0.0,
                };
                let s_string = match (sfp_a, sfp_b) {
                    (Some(a), Some(b)) => string_similarity(a, b),
                    _ => 0.0,
                };
                let s = wl_weight * s_wl + api_weight * s_api + string_weight * s_string;
                if s > best_s {
                    best_s = s;
                    best_j = j as i32;
                }
            }
            (i, best_j, best_s)
        })
        .collect()
}

fn greedy_assign(
    old_best: &mut [(usize, i32, f64)],
    old_names: &[String],
    new_names: &[String],
    match_threshold: f64,
    change_threshold: f64,
    allow_default_many: bool,
) -> (Vec<MatchEntry>, FxHashSet<usize>) {
    let mut results = Vec::new();
    let mut used_new: FxHashSet<usize> = FxHashSet::default();

    old_best.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());

    for &(i, best_j, best_s) in old_best.iter() {
        let can_assign = if best_j >= 0 && best_s >= change_threshold {
            let is_default = new_names[best_j as usize].is_empty();
            if is_default && allow_default_many {
                true
            } else {
                !used_new.contains(&(best_j as usize))
            }
        } else {
            false
        };

        if can_assign {
            let is_default = new_names[best_j as usize].is_empty();
            if !is_default || !allow_default_many {
                used_new.insert(best_j as usize);
            }
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

    (results, used_new)
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
    old: &SideData,
    new: &SideData,
    params: &MatchParams,
    old_parents: &FxHashMap<String, Vec<String>>,
    new_parents: &FxHashMap<String, Vec<String>>,
) -> Vec<MatchEntry> {
    let (wl_weight, api_weight, string_weight, hier_weight) = effective_weights(params);

    let mut old_best = compute_scores(old, new, wl_weight, api_weight, string_weight);

    let (mut results, _) = if hier_weight <= 0.0 {
        greedy_assign(
            &mut old_best,
            old.names,
            new.names,
            params.match_threshold,
            params.change_threshold,
            true,
        )
    } else {
        // Pass 1: initial greedy assignment
        let (pass1_results, _) = greedy_assign(
            &mut old_best,
            old.names,
            new.names,
            params.match_threshold,
            params.change_threshold,
            true,
        );

        // Build match map from pass 1 results
        let mut match_map: FxHashMap<String, (String, f64)> = FxHashMap::default();
        for (on, nn, score, status) in &pass1_results {
            if status != "REMOVED" && status != "NEW" && *score > 0.0 {
                match_map.insert(on.clone(), (nn.clone(), *score));
            }
        }

        // Pass 2: compute refined scores with hierarchical consistency bonus
        let mut old_best_refined: Vec<(usize, i32, f64)> = old
            .names
            .par_iter()
            .enumerate()
            .map(|(i, on)| {
                let sig_a = &old.sigs[on];
                let fp_a = old.api_fps.get(on);
                let sfp_a = old.string_fps.get(on);
                let mut best_j = -1i32;
                let mut best_s = 0.0f64;
                for (j, nn) in new.names.iter().enumerate() {
                    let sig_b = &new.sigs[nn];
                    let fp_b = new.api_fps.get(nn);
                    let sfp_b = new.string_fps.get(nn);
                    let s_wl = wl_similarity(&sig_a.hists, &sig_b.hists);
                    let s_api = match (fp_a, fp_b) {
                        (Some(a), Some(b)) => api_similarity(a, b),
                        _ => 0.0,
                    };
                    let s_string = match (sfp_a, sfp_b) {
                        (Some(a), Some(b)) => string_similarity(a, b),
                        _ => 0.0,
                    };
                    let base_s = wl_weight * s_wl + api_weight * s_api + string_weight * s_string;
                    let hier_factor = if base_s > 0.0 {
                        let n_consistent = ancestor_chain(on)
                            .iter()
                            .zip(ancestor_chain(nn).iter())
                            .filter(|(oa, na)| {
                                match_map.get(oa.as_str()).map(|(m, _)| m.as_str())
                                    == Some(na.as_str())
                            })
                            .count();
                        let n_levels = ancestor_chain(on)
                            .len()
                            .min(ancestor_chain(nn).len())
                            .max(1);
                        1.0 + hier_weight * (n_consistent as f64 / n_levels as f64)
                    } else {
                        1.0
                    };
                    let s = (base_s * hier_factor).min(1.0);
                    if s > best_s {
                        best_s = s;
                        best_j = j as i32;
                    }
                }
                (i, best_j, best_s)
            })
            .collect();

        greedy_assign(
            &mut old_best_refined,
            old.names,
            new.names,
            params.match_threshold,
            params.change_threshold,
            true,
        )
    };

    // Match no-graph packages using hierarchy context
    {
        let mut match_map: FxHashMap<String, (String, f64)> = FxHashMap::default();
        let mut used_new_names: FxHashSet<&str> = FxHashSet::default();
        for (on, nn, score, status) in &results {
            if status != "REMOVED" && status != "NEW" && *score > 0.0 {
                match_map.insert(on.clone(), (nn.clone(), *score));
                used_new_names.insert(nn.as_str());
            }
        }
        let empty_results = match_empty_packages(
            old,
            new,
            old_parents,
            new_parents,
            &match_map,
            &used_new_names,
        );
        results.extend(empty_results);
    }

    if params.use_node_matching {
        for (old_name, new_name, score, status) in &mut results {
            if (*status == "MATCH" || *status == "CHANGED")
                && let (Some(sig_a), Some(sig_b)) = (old.sigs.get(old_name), new.sigs.get(new_name))
            {
                *score *= node_label_consistency(sig_a, sig_b);
                if *score < params.change_threshold {
                    *status = "REMOVED".to_string();
                } else if *score < params.match_threshold {
                    *status = "CHANGED".to_string();
                }
            }
        }
    }

    results
}

fn parent_path(pkg: &str) -> Option<String> {
    pkg.rfind('/').map(|pos| pkg[..pos].to_string())
}

fn ancestor_chain(pkg: &str) -> Vec<String> {
    let mut chain = Vec::new();
    let mut current = parent_path(pkg);
    while let Some(ref p) = current {
        chain.push(p.clone());
        current = parent_path(p);
    }
    chain
}

fn build_parent_map(names: &[String]) -> FxHashMap<String, Vec<String>> {
    let mut map: FxHashMap<String, Vec<String>> = FxHashMap::default();
    for name in names {
        if let Some(parent) = parent_path(name) {
            map.entry(parent).or_default().push(name.clone());
        }
    }
    map
}

fn match_empty_packages(
    old: &SideData,
    new: &SideData,
    _old_parent_map: &FxHashMap<String, Vec<String>>,
    _new_parent_map: &FxHashMap<String, Vec<String>>,
    match_map: &FxHashMap<String, (String, f64)>,
    used_new_main: &FxHashSet<&str>,
) -> Vec<MatchEntry> {
    let mut results = Vec::new();
    let mut used_old = FxHashSet::default();
    let mut used_new = FxHashSet::default();

    // All new package names; avoid re-matching packages already claimed in the main pass
    let new_all: FxHashSet<&str> = new
        .names
        .iter()
        .chain(new.no_graph.iter())
        .filter(|n| !used_new_main.contains(n.as_str()))
        .map(|s| s.as_str())
        .collect();
    for old_pkg in old.no_graph {
        if match_map.contains_key(old_pkg) {
            continue;
        }
        let old_parent = parent_path(old_pkg);

        // Try to match old empty against new empties by same name or parent context
        for new_pkg in new.no_graph {
            if used_new.contains(new_pkg) {
                continue;
            }
            let new_parent = parent_path(new_pkg);
            if old_parent == new_parent {
                if old_pkg == new_pkg {
                    results.push((old_pkg.clone(), new_pkg.clone(), 1.0, "MATCH".to_string()));
                    used_old.insert(old_pkg.clone());
                    used_new.insert(new_pkg.clone());
                    break;
                } else if let (Some(op), Some(np)) = (&old_parent, &new_parent)
                    && let Some((matched_new, _)) = match_map.get(op)
                    && matched_new == np
                {
                    results.push((old_pkg.clone(), new_pkg.clone(), 1.0, "MATCH".to_string()));
                    used_old.insert(old_pkg.clone());
                    used_new.insert(new_pkg.clone());
                    break;
                }
            }
        }

        // Fallback: match old empty against new packages WITH graphs by same name
        if !used_old.contains(old_pkg) && new_all.contains(old_pkg.as_str()) {
            results.push((old_pkg.clone(), old_pkg.clone(), 1.0, "MATCH".to_string()));
            used_old.insert(old_pkg.clone());
            used_new.insert(old_pkg.clone());
        }

        if !used_old.contains(old_pkg) {
            results.push((
                old_pkg.clone(),
                "---".to_string(),
                0.0,
                "REMOVED".to_string(),
            ));
            used_old.insert(old_pkg.clone());
        }
    }
    for new_pkg in new.no_graph {
        if !used_new.contains(new_pkg) {
            results.push(("---".to_string(), new_pkg.clone(), 0.0, "NEW".to_string()));
        }
    }
    results
}

/// High-level entry point: build package graphs for both APKs, run WL
/// matching, and return a `MatchResult` with similarity scores.
pub fn run_match(
    old_classes: &[SmaliClass],
    new_classes: &[SmaliClass],
    params: &MatchParams,
) -> MatchResult {
    let (old_data, old_method_counts, old_api_fps, old_string_fps) =
        build_package_graphs(old_classes, &params.excluded_features);
    let (new_data, new_method_counts, new_api_fps, new_string_fps) =
        build_package_graphs(new_classes, &params.excluded_features);
    let dim_mask = feature_dim_mask(&params.excluded_features);
    let (old_sigs, new_sigs, old_names, new_names, old_no_graph, new_no_graph) =
        compute_sigs_and_names(&old_data, &new_data, params.wl_iterations, &dim_mask);

    let old = SideData {
        sigs: &old_sigs,
        names: &old_names,
        no_graph: &old_no_graph,
        api_fps: &old_api_fps,
        string_fps: &old_string_fps,
    };
    let new = SideData {
        sigs: &new_sigs,
        names: &new_names,
        no_graph: &new_no_graph,
        api_fps: &new_api_fps,
        string_fps: &new_string_fps,
    };

    let all_old_names: Vec<String> = old
        .names
        .iter()
        .chain(old.no_graph.iter())
        .cloned()
        .collect();
    let all_new_names: Vec<String> = new
        .names
        .iter()
        .chain(new.no_graph.iter())
        .cloned()
        .collect();
    let old_parents = build_parent_map(&all_old_names);
    let new_parents = build_parent_map(&all_new_names);

    let results = match_packages(&old, &new, params, &old_parents, &new_parents);

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
        let f1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0, 0, 0, 0];
        let f2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0, 0, 0, 0];
        assert_eq!(hash_features(&f1), hash_features(&f2));
    }

    #[test]
    fn test_hash_features_different() {
        let f1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0, 0, 0, 0];
        let f2 = [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 0, 0, 0, 0, 0];
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
        let (features, calls, api, strings) = extract_method_features(&method, "com/example");
        assert_eq!(features[IDX_NUM_PARAMS], 0);
        assert_eq!(features[IDX_NUM_INSTRUCTIONS], 0);
        assert_eq!(features[IDX_OUT_DEGREE], 0);
        assert_eq!(features[IDX_STRING_CONSTS], 0);
        assert_eq!(features[IDX_FIELD_ACCESS], 0);
        assert_eq!(features[IDX_TRY_CATCH], 0);
        assert_eq!(features[IDX_REGISTER_COUNT], 0);
        assert_eq!(features[IDX_IS_CONSTRUCTOR], 0);
        assert_eq!(features[IDX_RETURN_TYPE], 0); // void return type
        assert!(calls.is_empty());
        assert!(api.is_empty());
        assert!(strings.is_empty());
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
        let (features, calls, api, strings) = extract_method_features(&method, "com/example");
        assert_eq!(features[IDX_INVOKE_VIRTUAL], 1);
        assert_eq!(features[IDX_NUM_INSTRUCTIONS], 1);
        assert_eq!(features[IDX_OUT_DEGREE], 1);
        assert_eq!(features[IDX_EXT_ANDROID], 1);
        assert_eq!(features[IDX_STRING_CONSTS], 0);
        assert_eq!(features[IDX_FIELD_ACCESS], 0);
        assert_eq!(features[IDX_TRY_CATCH], 0);
        assert_eq!(features[IDX_REGISTER_COUNT], 0);
        assert_eq!(features[IDX_IS_CONSTRUCTOR], 0);
        assert_eq!(features[IDX_RETURN_TYPE], 0); // void return type
        assert!(calls.is_empty()); // not internal to com/example
        assert_eq!(api.len(), 1); // one external API call recorded
        assert!(strings.is_empty());
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
        let (features, calls, api, strings) = extract_method_features(&method, pkg);
        assert_eq!(features[IDX_INVOKE_STATIC], 1);
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("internalMethod"));
        assert!(api.is_empty()); // internal call, not external
        assert!(strings.is_empty());
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
        let (features, _, _, _) = extract_method_features(&method, "com/example");
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
        let features = [[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]];
        let sig = wl_histograms(&adj, &features, 2, &[false; 19]);
        assert_eq!(sig.hists.len(), 3); // 0, 1, 2 iterations
        for hist in &sig.hists {
            assert_eq!(hist.len(), 1); // single node, single label
        }
    }

    #[test]
    fn test_wl_histograms_two_nodes() {
        let adj = vec![vec![1], vec![0]];
        let features = [
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        let sig = wl_histograms(&adj, &features, 1, &[false; 19]);
        assert_eq!(sig.hists.len(), 2);
        // initial hist should have 2 distinct labels
        assert_eq!(sig.hists[0].len(), 2);
    }

    #[test]
    fn test_wl_histograms_masked_dimension() {
        // Two nodes differing only in dimension 0 collapse to one label when
        // that dimension is masked.
        let adj = vec![vec![1], vec![0]];
        let features = [
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        let mut mask = [false; 19];
        mask[IDX_IN_DEGREE] = true;
        let sig = wl_histograms(&adj, &features, 1, &mask);
        assert_eq!(sig.hists[0].len(), 1); // masked dim no longer separates nodes
    }

    #[test]
    fn test_feature_dim_mask_none_excluded() {
        let mask = feature_dim_mask(&[]);
        assert!(mask.iter().all(|&m| !m));
    }

    #[test]
    fn test_feature_dim_mask_single_dimension() {
        let mask = feature_dim_mask(&[Feature::HasBranches]);
        let mut expect = [false; 19];
        expect[IDX_HAS_BRANCHES] = true;
        assert_eq!(mask, expect);
    }

    #[test]
    fn test_feature_dim_mask_multiple() {
        let mask = feature_dim_mask(&[
            Feature::NumParams,
            Feature::StringConsts,
            Feature::ReturnType,
        ]);
        assert!(mask[IDX_NUM_PARAMS]);
        assert!(mask[IDX_STRING_CONSTS]);
        assert!(mask[IDX_RETURN_TYPE]);
        assert_eq!(mask.iter().filter(|&&m| m).count(), 3);
    }

    #[test]
    fn test_feature_dim_mask_api_categories_map_to_ext_dims() {
        let mask = feature_dim_mask(&[Feature::ApiAndroid, Feature::ApiJava]);
        assert!(mask[IDX_EXT_ANDROID]);
        assert!(mask[IDX_EXT_JAVA]);
        assert!(!mask[IDX_EXT_KOTLIN]);
        // androidx shares the ext_android dimension
        assert!(feature_dim_mask(&[Feature::ApiAndroidx])[IDX_EXT_ANDROID]);
    }

    #[test]
    fn test_feature_dim_mask_coarse_features_ignored() {
        let mask = feature_dim_mask(&[Feature::Wl, Feature::Api, Feature::String, Feature::Hier]);
        assert!(mask.iter().all(|&m| !m));
    }

    #[test]
    fn test_is_api_category_excluded() {
        let excluded = [Feature::ApiAndroid, Feature::ApiKotlin];
        assert!(is_api_category_excluded(
            &excluded,
            "Landroid/app/Activity;"
        ));
        assert!(is_api_category_excluded(
            &excluded,
            "Lkotlin/jvm/internal/Intrinsics;"
        ));
        assert!(!is_api_category_excluded(&excluded, "Ljava/lang/String;"));
        assert!(!is_api_category_excluded(&excluded, "Lcom/example/Foo;"));
        assert!(!is_api_category_excluded(
            &[Feature::Wl],
            "Landroid/app/Activity;"
        ));
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
        let empty_fps: ApiFingerprints = FxHashMap::default();
        let empty_sfps: StringFingerprints = FxHashMap::default();
        let old_sd = SideData {
            sigs: &old_sigs,
            names: &old_names,
            no_graph: &[],
            api_fps: &empty_fps,
            string_fps: &empty_sfps,
        };
        let new_sd = SideData {
            sigs: &new_sigs,
            names: &new_names,
            no_graph: &[],
            api_fps: &empty_fps,
            string_fps: &empty_sfps,
        };
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.0,
            hier_weight: 0.0,
            string_weight: 0.0,
            excluded_features: vec![],
        };
        let results = match_packages(
            &old_sd,
            &new_sd,
            &params,
            &FxHashMap::default(),
            &FxHashMap::default(),
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
        let empty_fps: ApiFingerprints = FxHashMap::default();
        let empty_sfps: StringFingerprints = FxHashMap::default();
        let old_sd = SideData {
            sigs: &old_sigs,
            names: &old_names,
            no_graph: &[],
            api_fps: &empty_fps,
            string_fps: &empty_sfps,
        };
        let new_sd = SideData {
            sigs: &new_sigs,
            names: &new_names,
            no_graph: &[],
            api_fps: &empty_fps,
            string_fps: &empty_sfps,
        };
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.0,
            hier_weight: 0.0,
            string_weight: 0.0,
            excluded_features: vec![],
        };
        let results = match_packages(
            &old_sd,
            &new_sd,
            &params,
            &FxHashMap::default(),
            &FxHashMap::default(),
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
        let empty_fps: ApiFingerprints = FxHashMap::default();
        let empty_sfps: StringFingerprints = FxHashMap::default();
        let old_sd = SideData {
            sigs: &old_sigs,
            names: &old_names,
            no_graph: &[],
            api_fps: &empty_fps,
            string_fps: &empty_sfps,
        };
        let new_sd = SideData {
            sigs: &new_sigs,
            names: &new_names,
            no_graph: &[],
            api_fps: &empty_fps,
            string_fps: &empty_sfps,
        };
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.0,
            hier_weight: 0.0,
            string_weight: 0.0,
            excluded_features: vec![],
        };
        let results = match_packages(
            &old_sd,
            &new_sd,
            &params,
            &FxHashMap::default(),
            &FxHashMap::default(),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].3, "NEW");
    }

    #[test]
    fn test_match_packages_no_graph() {
        let empty_fps: ApiFingerprints = FxHashMap::default();
        let empty_sfps: StringFingerprints = FxHashMap::default();
        let old_sd = SideData {
            sigs: &FxHashMap::default(),
            names: &[],
            no_graph: &["pkgEmpty".to_string()],
            api_fps: &empty_fps,
            string_fps: &empty_sfps,
        };
        let new_sd = SideData {
            sigs: &FxHashMap::default(),
            names: &[],
            no_graph: &[],
            api_fps: &empty_fps,
            string_fps: &empty_sfps,
        };
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.0,
            hier_weight: 0.0,
            string_weight: 0.0,
            excluded_features: vec![],
        };
        let results = match_packages(
            &old_sd,
            &new_sd,
            &params,
            &FxHashMap::default(),
            &FxHashMap::default(),
        );
        assert!(
            results
                .iter()
                .any(|r| r.0 == "pkgEmpty" && r.3 == "REMOVED")
        );
    }

    #[test]
    fn test_effective_weights_defaults() {
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.2,
            hier_weight: 0.7,
            string_weight: 0.3,
            excluded_features: vec![],
        };
        let (wl, api, string, hier) = effective_weights(&params);
        assert!((wl - 0.5).abs() < 1e-9);
        assert!((api - 0.2).abs() < 1e-9);
        assert!((string - 0.3).abs() < 1e-9);
        assert!((hier - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_effective_weights_exclude_api() {
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.2,
            hier_weight: 0.7,
            string_weight: 0.3,
            excluded_features: vec![Feature::Api],
        };
        let (wl, api, string, hier) = effective_weights(&params);
        assert!((wl - 0.625).abs() < 1e-9);
        assert!(api == 0.0);
        assert!((string - 0.375).abs() < 1e-9);
        assert!((hier - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_effective_weights_exclude_string() {
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.2,
            hier_weight: 0.7,
            string_weight: 0.3,
            excluded_features: vec![Feature::String],
        };
        let (wl, api, string, hier) = effective_weights(&params);
        assert!((wl - 0.5 / 0.7).abs() < 1e-9);
        assert!((api - 0.2 / 0.7).abs() < 1e-9);
        assert!(string == 0.0);
        assert!((hier - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_effective_weights_exclude_wl() {
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.2,
            hier_weight: 0.7,
            string_weight: 0.3,
            excluded_features: vec![Feature::Wl],
        };
        let (wl, api, string, hier) = effective_weights(&params);
        assert!(wl == 0.0);
        assert!((api - 0.4).abs() < 1e-9);
        assert!((string - 0.6).abs() < 1e-9);
        assert!((hier - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_effective_weights_exclude_hier() {
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.2,
            hier_weight: 0.7,
            string_weight: 0.3,
            excluded_features: vec![Feature::Hier],
        };
        let (wl, api, string, hier) = effective_weights(&params);
        assert!((wl - 0.5).abs() < 1e-9);
        assert!((api - 0.2).abs() < 1e-9);
        assert!((string - 0.3).abs() < 1e-9);
        assert!(hier == 0.0);
    }

    #[test]
    fn test_effective_weights_exclude_all() {
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.2,
            hier_weight: 0.7,
            string_weight: 0.3,
            excluded_features: vec![Feature::Wl, Feature::Api, Feature::String, Feature::Hier],
        };
        let (wl, api, string, hier) = effective_weights(&params);
        assert!(wl == 0.0 && api == 0.0 && string == 0.0 && hier == 0.0);
    }

    #[test]
    fn test_effective_weights_exclude_default_pool() {
        let params = MatchParams {
            match_threshold: 0.8,
            change_threshold: 0.0,
            wl_iterations: 0,
            use_node_matching: false,
            api_weight: 0.0,
            hier_weight: 0.7,
            string_weight: 0.0,
            excluded_features: vec![Feature::Wl],
        };
        // WL excluded and both api/string weights are 0: no retained weight remains.
        let (wl, api, string, _hier) = effective_weights(&params);
        assert!(wl == 0.0 && api == 0.0 && string == 0.0);
    }
}
