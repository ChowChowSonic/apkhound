//! Iterate over DEX entries in an APK and build a call graph by extracting
//! all `Invoke*` opcodes from every method. Output is a
//! `HashMap<caller_sig, Vec<callee_sig>>`.

use crate::utils::is_match_allowed;
use rayon::iter::{IntoParallelRefIterator, ParallelBridge, ParallelIterator};
use regex::Regex;
use rustc_hash::FxHashMap;
use smali::android::zip::is_top_level_dex_name;
use smali::dex::DexFile;
use smali::smali_ops::DexOp;
use smali::types::SmaliMethod;
use smali::{android::zip::ApkFile, types::SmaliClass, types::SmaliOp};
use tracing::error;
fn jni_class_to_java(jni: &str) -> String {
    jni.strip_prefix('L')
        .unwrap_or(jni)
        .strip_suffix(';')
        .unwrap_or(jni)
        .replace('/', ".")
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
    accum: &mut FxHashMap<String, Vec<String>>,
) {
    let tempres = self_method
        .ops
        .iter()
        .par_bridge()
        .fold(FxHashMap::default, |mut accum2, op| {
            let sig = format!("{}:{}", classname, self_method.name);
            match op {
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

fn iterate_through_dex_functions(class: &SmaliClass, accum: &mut FxHashMap<String, Vec<String>>) {
    let tempres = class
        .methods
        .iter()
        .par_bridge()
        .fold(FxHashMap::default, |mut accum2, self_method| {
            iterate_over_function(self_method, &class.name.as_java_type(), &mut accum2);
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
    accum: &mut FxHashMap<String, Vec<String>>,
) {
    if let Ok(classes) = dex.to_smali() {
        let tmpres = classes
            .iter()
            .filter(|val| is_match_allowed(&val.name.as_java_type(), whitelist, blacklist))
            .par_bridge()
            .fold(FxHashMap::default, |mut accum2, class| {
                iterate_through_dex_functions(class, &mut accum2);
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
pub fn iterate_over_dex_files(
    apk: &ApkFile,
    whitelist: &[Regex],
    blacklist: &[Regex],
) -> FxHashMap<String, Vec<String>> {
    let entry_names: Vec<_> = apk
        .entry_names()
        .filter(|x| is_top_level_dex_name(x))
        .collect();
    entry_names.par_iter()
        .fold( FxHashMap::default, |mut accum, x| {
            let entry_res = apk.entry(x);
            if let Some(entry) = entry_res {
                let dex_result = DexFile::from_bytes(&entry.data);
                if let Ok(dex) = dex_result {
                    iterate_through_dex_file(dex, whitelist, blacklist, &mut accum);
                } else if let Err(e) = dex_result {
                    error!("Failed to create dex file from binary code provided by entry {x:?} due to reason: {e}");
                }
            };
            accum
        })
        .reduce(FxHashMap::default, |mut accum, res| {
            merge_call_graphs(&mut accum, res);
            accum
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jni_class_to_java_simple() {
        assert_eq!(jni_class_to_java("Lcom/example/Test;"), "com.example.Test");
    }

    #[test]
    fn test_jni_class_to_java_inner() {
        assert_eq!(
            jni_class_to_java("Lcom/example/Outer$Inner;"),
            "com.example.Outer$Inner"
        );
    }

    #[test]
    fn test_jni_class_to_java_no_leading_l() {
        assert_eq!(jni_class_to_java("java/lang/String"), "java.lang.String");
    }

    #[test]
    fn test_jni_class_to_java_no_semicolon() {
        // Without ';' the fallback keeps the 'L' prefix
        assert_eq!(jni_class_to_java("Ljava/lang/Object"), "Ljava.lang.Object");
    }

    #[test]
    fn test_jni_class_to_java_array() {
        // Array prefix '[' prevents 'L' stripping, but ';' is stripped
        assert_eq!(
            jni_class_to_java("[Ljava/lang/String;"),
            "[Ljava.lang.String"
        );
    }

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
        iterate_through_dex_functions(&cls, &mut graph);

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
}
