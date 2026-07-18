//! Iterate over DEX entries in an APK and build a call graph by extracting
//! all `Invoke*` opcodes from every method. Output is a
//! `HashMap<caller_sig, Vec<callee_sig>>`.

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

fn iterate_over_function(
    self_method: &SmaliMethod,
    classname: &String,
    accum: &mut FxHashMap<String, Vec<String>>,
) {
    let mut tempres = self_method
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
        .reduce(FxHashMap::default, |mut cumul, mut res| {
            for (key, values) in res.drain() {
                cumul.entry(key).or_default().extend(values);
            }

            cumul
        });
    tempres.values_mut().for_each(|v| {
        v.sort();
        v.dedup();
    });
    accum.extend(tempres.drain());
}

fn iterate_through_dex_functions(class: &SmaliClass, accum: &mut FxHashMap<String, Vec<String>>) {
    let mut tempres = class
        .methods
        .iter()
        .par_bridge()
        .fold(FxHashMap::default, |mut accum2, self_method| {
            iterate_over_function(self_method, &class.name.as_java_type(), &mut accum2);
            accum2
        })
        .reduce(FxHashMap::default, |mut accum3, mut res| {
            accum3.extend(res.drain());
            accum3
        });
    accum.extend(tempres.drain());
}

fn iterate_through_dex_file(
    dex: DexFile,
    filters: &[Regex],
    accum: &mut FxHashMap<String, Vec<String>>,
) {
    if let Ok(classes) = dex.to_smali() {
        let mut tmpres = classes
            .iter()
            .filter(|val| {
                filters.is_empty()
                    || filters
                        .iter()
                        .any(|reg| reg.is_match(&val.name.as_java_type()))
            })
            .par_bridge()
            .fold(FxHashMap::default, |mut accum2, class| {
                iterate_through_dex_functions(class, &mut accum2);
                accum2
            })
            .reduce(FxHashMap::default, |mut tmp, mut res| {
                tmp.extend(res.drain());
                tmp
            });
        accum.extend(tmpres.drain());
    }
}

/// Walk every top-level DEX file inside an APK, parse its classes, and
/// return a map from caller signature (class:method) to the list of callee
/// signatures it invokes.  Classes can be filtered by a list of regexes.
pub fn iterate_over_dex_files(apk: &ApkFile, filters: &[Regex]) -> FxHashMap<String, Vec<String>> {
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
                    iterate_through_dex_file(dex, filters, &mut accum);
                } else if let Err(e) = dex_result {
                    error!("Failed to create dex file from binary code provided by entry {x:?} due to reason: {e}");
                }
            };
            accum
        })
        .reduce(FxHashMap::default, |mut accum, mut res| {
            accum.extend(res.drain());
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
}
