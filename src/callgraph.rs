//! Iterate over DEX entries in an APK and build a call graph by extracting
//! all `Invoke*` opcodes from every method. Output is a
//! `HashMap<caller_sig, Vec<callee_sig>>`.

use crate::utils::{
    is_match_allowed, jni_class_to_java, read_u16, read_u32, read_uleb128, resolve_method_sig,
};
use rayon::iter::{IntoParallelRefIterator, ParallelBridge, ParallelIterator};
use regex::Regex;
use rustc_hash::FxHashMap;
use smali::android::zip::is_top_level_dex_name;
use smali::dex::DexFile;
use smali::smali_ops::DexOp;
use smali::types::SmaliMethod;
use smali::{android::zip::ApkFile, types::SmaliClass, types::SmaliOp};
use tracing::error;

/// Parse DEX `call_site_ids` -> `encoded_array` -> `method_handles` and return a map
/// from `"call_site_N"` to `"com.example.Class:lambda$..."`.
fn extract_call_sites(data: &[u8]) -> FxHashMap<String, String> {
    let mut out = FxHashMap::default();
    let Some(map_off) = read_u32(data, 0x34).map(|o| o as usize) else {
        return out;
    };
    let Some(map_size) = read_u32(data, map_off).map(|s| s as usize) else {
        return out;
    };

    let mut call_site_ids: Option<(usize, usize)> = None; // (offset, count)
    let mut method_handles: Option<(usize, usize)> = None;

    for i in 0..map_size {
        let entry_off = map_off + 4 + i * 12;
        let Some(item_type) = read_u16(data, entry_off) else {
            break;
        };
        let Some(size) = read_u32(data, entry_off + 4).map(|s| s as usize) else {
            break;
        };
        let Some(offset) = read_u32(data, entry_off + 8).map(|o| o as usize) else {
            break;
        };
        match item_type {
            0x0007 => call_site_ids = Some((offset, size)),
            0x0008 => method_handles = Some((offset, size)),
            _ => {}
        }
    }

    let (Some((cs_off, cs_count)), Some((mh_off, mh_count))) = (call_site_ids, method_handles)
    else {
        return out;
    };

    for idx in 0..cs_count {
        let Some(arr_off) = read_u32(data, cs_off + idx * 4).map(|o| o as usize) else {
            continue;
        };
        let mut cursor = arr_off;
        let Some(elem_count) = read_uleb128(data, &mut cursor) else {
            continue;
        };

        // Decode the encoded_array items; index 4 is LambdaMetafactory's implMethod handle.
        let mut handle_indices: Vec<(usize, u32)> = Vec::new();
        for elem_idx in 0..elem_count as usize {
            let Some(&header) = data.get(cursor) else {
                break;
            };
            cursor += 1;
            let value_type = header & 0x1f;
            let value_arg = (header >> 5) as usize;

            match value_type {
                0x1e | 0x1f => {}     // VALUE_NULL / VALUE_BOOLEAN (0 payload bytes)
                0x1c | 0x1d => break, // Nested array/annotation not used in LambdaMetafactory
                _ => {
                    let byte_len = value_arg + 1;
                    let Some(bytes) = data.get(cursor..cursor + byte_len) else {
                        break;
                    };
                    cursor += byte_len;

                    if value_type == 0x16 {
                        // VALUE_METHOD_HANDLE (little-endian unsigned index)
                        let mut val = 0u32;
                        for (shift_i, &b) in bytes.iter().enumerate() {
                            val |= (b as u32) << (shift_i * 8);
                        }
                        handle_indices.push((elem_idx, val));
                    }
                }
            }
        }

        // Verify bootstrap handle [0] is LambdaMetafactory and resolve target handle [4]
        let Some(&(_, bsm_mh_idx)) = handle_indices.iter().find(|&&(i, _)| i == 0) else {
            continue;
        };
        let Some(&(_, impl_mh_idx)) = handle_indices.iter().find(|&&(i, _)| i == 4) else {
            continue;
        };
        if (bsm_mh_idx as usize) >= mh_count || (impl_mh_idx as usize) >= mh_count {
            continue;
        }

        let bsm_item = mh_off + (bsm_mh_idx as usize) * 8;
        let Some(bsm_method_id) = read_u16(data, bsm_item + 4) else {
            continue;
        };
        let Some(bsm_sig) = resolve_method_sig(data, bsm_method_id as usize) else {
            continue;
        };
        if !bsm_sig.starts_with("java.lang.invoke.LambdaMetafactory:") {
            continue;
        }

        let impl_item = mh_off + (impl_mh_idx as usize) * 8;
        let Some(mh_type) = read_u16(data, impl_item) else {
            continue;
        };
        let Some(impl_method_id) = read_u16(data, impl_item + 4) else {
            continue;
        };
        // 0x04..=0x08 are method handles (as opposed to 0x00..=0x03 field handles)
        if (0x04..=0x08).contains(&mh_type) {
            if let Some(target_sig) = resolve_method_sig(data, impl_method_id as usize) {
                out.insert(format!("call_site_{idx}"), target_sig);
            }
        }
    }

    out
}

/// D8/R8 desugar lambdas into synthetic classes named
/// `Foo$$ExternalSyntheticLambdaN`.  The caller only records a constructor
/// call plus the framework dispatch (`Executor.execute`, `View.post`, ...);
/// the eventual callback (`run`, `accept`, ...) is invoked through the
/// functional interface at runtime, so the graph has no edge from the caller
/// to the lambda body.
///
/// For every `caller -> Lambda:<init>` edge, add an edge from `caller` to
/// each non-constructor method declared by `Lambda`. This is conservative:
/// constructing a lambda does not guarantee it runs, but it restores the
/// callback chain that the bytecode split across synthetic classes.
pub fn bridge_desugared_lambdas(graph: &mut FxHashMap<String, Vec<String>>) {
    // Synthetic lambda class -> its callback method(s), e.g. `...Lambda10 -> run`.
    let mut callbacks: FxHashMap<String, Vec<String>> = FxHashMap::default();
    for key in graph.keys() {
        let Some((class, method)) = key.rsplit_once(':') else {
            continue;
        };
        if class.contains("$$ExternalSyntheticLambda") && method != "<init>" {
            callbacks
                .entry(class.to_string())
                .or_default()
                .push(method.to_string());
        }
    }
    if callbacks.is_empty() {
        return;
    }

    let mut extra: Vec<(String, String)> = Vec::new();
    for (caller, callees) in graph.iter() {
        for callee in callees {
            let Some((class, method)) = callee.rsplit_once(':') else {
                continue;
            };
            if method != "<init>" {
                continue;
            }
            if let Some(methods) = callbacks.get(class) {
                for callback in methods {
                    extra.push((caller.clone(), format!("{class}:{callback}")));
                }
            }
        }
    }

    for (caller, callback) in extra {
        graph.entry(caller).or_default().push(callback);
    }
    for callees in graph.values_mut() {
        callees.sort();
        callees.dedup();
    }
}

fn merge_call_graphs(
    target: &mut FxHashMap<String, Vec<String>>,
    mut source: FxHashMap<String, Vec<String>>,
) {
    for (key, values) in source.drain() {
        let entry = target.entry(key).or_default();
        entry.extend(values);
        entry.sort();
        entry.dedup();
    }
}

fn iterate_over_function(
    self_method: &SmaliMethod,
    classname: &str,
    call_sites: &FxHashMap<String, String>,
    accum: &mut FxHashMap<String, Vec<String>>,
) {
    let tempres = self_method
        .ops
        .iter()
        .par_bridge()
        .fold(FxHashMap::default, |mut accum2, op| {
            let sig = format!("{}:{}", classname, self_method.name);
            match op {
                SmaliOp::Op(DexOp::InvokeCustom { call_site, .. })
                | SmaliOp::Op(DexOp::InvokeCustomRange { call_site, .. }) => {
                    if let Some(target_sig) = call_sites.get(call_site) {
                        accum2.entry(sig).or_insert(vec![]).push(target_sig.clone());
                    }
                }
                SmaliOp::Op(DexOp::InvokeVirtual { method, .. })
                | SmaliOp::Op(DexOp::InvokeSuper { method, .. })
                | SmaliOp::Op(DexOp::InvokeInterface { method, .. })
                | SmaliOp::Op(DexOp::InvokeDirect { method, .. })
                | SmaliOp::Op(DexOp::InvokeStatic { method, .. })
                | SmaliOp::Op(DexOp::InvokeVirtualRange { method, .. })
                | SmaliOp::Op(DexOp::InvokeSuperRange { method, .. })
                | SmaliOp::Op(DexOp::InvokeDirectRange { method, .. })
                | SmaliOp::Op(DexOp::InvokeStaticRange { method, .. })
                | SmaliOp::Op(DexOp::InvokeInterfaceRange { method, .. })
                | SmaliOp::Op(DexOp::InvokePolymorphic { method, .. })
                | SmaliOp::Op(DexOp::InvokePolymorphicRange { method, .. }) => {
                    let invoked_sig =
                        format!("{}:{}", jni_class_to_java(&method.class), method.name);
                    accum2.entry(sig).or_insert(vec![]).push(invoked_sig);
                }
                _ => {}
            };
            accum2
        })
        .reduce(FxHashMap::default, |mut cumul, res| {
            merge_call_graphs(&mut cumul, res);
            cumul
        });
    merge_call_graphs(accum, tempres);
}

fn iterate_through_dex_functions(
    class: &SmaliClass,
    call_sites: &FxHashMap<String, String>,
    accum: &mut FxHashMap<String, Vec<String>>,
) {
    let tempres = class
        .methods
        .iter()
        .par_bridge()
        .fold(FxHashMap::default, |mut accum2, self_method| {
            iterate_over_function(
                self_method,
                &class.name.as_java_type(),
                &call_sites,
                &mut accum2,
            );
            accum2
        })
        .reduce(FxHashMap::default, |mut accum3, res| {
            merge_call_graphs(&mut accum3, res);
            accum3
        });
    merge_call_graphs(accum, tempres);
}

fn iterate_through_dex_file(
    dex: DexFile,
    whitelist: &[Regex],
    blacklist: &[Regex],
    call_sites: &FxHashMap<String, String>,
    accum: &mut FxHashMap<String, Vec<String>>,
) {
    if let Ok(classes) = dex.to_smali() {
        let tmpres = classes
            .iter()
            .filter(|val| is_match_allowed(&val.name.as_java_type(), whitelist, blacklist))
            .par_bridge()
            .fold(FxHashMap::default, |mut accum2, class| {
                iterate_through_dex_functions(class, &call_sites, &mut accum2);
                accum2
            })
            .reduce(FxHashMap::default, |mut tmp, res| {
                merge_call_graphs(&mut tmp, res);
                tmp
            });
        merge_call_graphs(accum, tmpres);
    }
}

/// Walk every top-level DEX file inside an APK, parse its classes, and
/// return a map from caller signature (class:method) to the list of callee
/// signatures it invokes. Classes can be filtered by whitelist and blacklist regexes.
///
/// When `bridge_lambdas` is true, desugared D8/R8 lambdas are bridged so that
/// callers that construct a synthetic lambda also point at its callback
/// method (see [`bridge_desugared_lambdas`]).
pub fn iterate_over_dex_files(
    apk: &ApkFile,
    whitelist: &[Regex],
    blacklist: &[Regex],
    bridge_lambdas: bool,
) -> FxHashMap<String, Vec<String>> {
    let entry_names: Vec<_> = apk
        .entry_names()
        .filter(|x| is_top_level_dex_name(x))
        .collect();
    let mut graph = entry_names
        .par_iter()
        .fold(FxHashMap::default, |mut accum, x| {
            let entry_res = apk.entry(x);
            if let Some(entry) = entry_res {
                let dex_result = DexFile::from_bytes(&entry.data);
                if let Ok(dex) = dex_result {
                    let call_sites = extract_call_sites(&entry.data);
                    iterate_through_dex_file(dex, whitelist, blacklist, &call_sites, &mut accum);
                } else if let Err(e) = dex_result {
                    error!("Failed to create dex file from binary code provided by entry {x:?} due to reason: {e}");
                }
            };
            accum
        })
        .reduce(FxHashMap::default, |mut accum, res| {
            merge_call_graphs(&mut accum, res);
            accum
        });
    if bridge_lambdas {
        bridge_desugared_lambdas(&mut graph);
    }
    graph
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callgraph_overloaded_methods_not_overwritten() {
        use smali::smali_ops::{DexOp, MethodRef};
        use smali::types::{MethodSignature, ObjectIdentifier, SmaliMethod, SmaliOp};

        let m1 = SmaliMethod {
            name: "work".to_string(),
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
                    class: "Lcom/example/CalleeA;".to_string(),
                    name: "methodA".to_string(),
                    descriptor: "()V".to_string(),
                },
            })],
        };

        let m2 = SmaliMethod {
            name: "work".to_string(),
            modifiers: vec![],
            constructor: false,
            signature: MethodSignature::from_jni("(I)V"),
            locals: 1,
            registers: None,
            params: vec![],
            annotations: vec![],
            ops: vec![SmaliOp::Op(DexOp::InvokeVirtual {
                registers: vec![],
                method: MethodRef {
                    class: "Lcom/example/CalleeB;".to_string(),
                    name: "methodB".to_string(),
                    descriptor: "(I)V".to_string(),
                },
            })],
        };

        let cls = SmaliClass {
            name: ObjectIdentifier::from_java_type("com.example.Worker"),
            modifiers: vec![],
            source: None,
            super_class: ObjectIdentifier::from_java_type("java.lang.Object"),
            implements: vec![],
            annotations: vec![],
            fields: vec![],
            methods: vec![m1, m2],
            file_path: None,
        };

        let mut graph = FxHashMap::default();
        let call_sites = FxHashMap::default();
        iterate_through_dex_functions(&cls, &call_sites, &mut graph);

        let callees = graph
            .get("com.example.Worker:work")
            .expect("caller key must exist");
        assert!(
            callees.contains(&"com.example.CalleeA:methodA".to_string()),
            "CalleeA should be present"
        );
        assert!(
            callees.contains(&"com.example.CalleeB:methodB".to_string()),
            "CalleeB should be present"
        );
        assert_eq!(
            callees.len(),
            2,
            "Both callees from overloaded methods must be present"
        );
    }

    fn graph(pairs: &[(&str, &[&str])]) -> FxHashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(caller, callees)| {
                (
                    caller.to_string(),
                    callees.iter().map(|callee| callee.to_string()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn test_bridge_adds_lambda_callback_edge() {
        let mut g = graph(&[
            (
                "com.example.Worker:work",
                &[
                    "com.example.Worker$$ExternalSyntheticLambda0:<init>",
                    "java.util.concurrent.ExecutorService:execute",
                ],
            ),
            (
                "com.example.Worker$$ExternalSyntheticLambda0:run",
                &["com.example.Worker:lambda$work$0"],
            ),
            (
                "com.example.Worker:lambda$work$0",
                &["com.example.Target:do"],
            ),
        ]);

        bridge_desugared_lambdas(&mut g);

        let callees = g.get("com.example.Worker:work").unwrap();
        assert!(
            callees.contains(&"com.example.Worker$$ExternalSyntheticLambda0:run".to_string()),
            "constructor call should be bridged to the lambda callback"
        );
    }

    #[test]
    fn test_bridge_ignores_regular_constructors() {
        let mut g = graph(&[
            ("com.example.Worker:work", &["com.example.Other:<init>"]),
            ("com.example.Other:<init>", &["java.lang.Object:<init>"]),
        ]);

        bridge_desugared_lambdas(&mut g);

        assert_eq!(
            g.get("com.example.Worker:work").unwrap(),
            &vec!["com.example.Other:<init>".to_string()],
            "non-lambda constructors must not gain callback edges"
        );
    }
}
