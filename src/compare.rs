//! APK comparison logic — extract classes from two APKs, diff them at the
//! method-signature level, and optionally dump changed smali to disk.

use rayon::prelude::*;
use regex::Regex;
use smali::android::zip::is_top_level_dex_name;
use smali::smali_ops::DexOp;
use smali::types::SmaliMethod;
use smali::{android::zip::ApkFile, dex::DexFile, types::SmaliClass, types::SmaliOp};
use rustc_hash::FxHashMap;
use std::fs::{File, create_dir_all};
use std::io::prelude::*;
use std::path::Path;
use tracing::error;

/// Describes a single edit found when comparing two versions of an APK.
pub enum EditType {
    /// A method's body changed between the old and new APK.
    Change(String),
    /// A method present in the old APK was removed from the new one.
    Remove(String),
    /// A method present in the new APK did not exist in the old one.
    Addition(String),
}

/// Build a human-readable Java-style method signature from a class name and
/// a `SmaliMethod`.
pub fn construct_java_signature(class: String, m: &SmaliMethod) -> String {
    let argslist: Vec<String> = m.signature.args.iter().map(|item| item.to_java()).collect();
    format!(
        "{}: {} {}({:?})",
        class,
        m.signature.result.to_java(),
        m.name,
        argslist
    )
}

fn method_filename(m: &SmaliMethod) -> String {
    let safe_name = m.name.replace(['<', '>'], "");
    let args: Vec<String> = m.signature.args.iter().map(|t| t.to_java()).collect();
    format!("{}({}).smali", safe_name, args.join(", "))
}

/// For each changed / added / removed method, write the old and new smali to
/// `output_dir/{old,new}/...`.  An optional list of `filters` restricts
/// which smali lines are written.
pub fn dump_changes_between_classes(
    new_classes: FxHashMap<String, SmaliClass>,
    old_classes: FxHashMap<String, SmaliClass>,
    output_dir_buf: &Path,
    filters: &[Regex],
) -> Result<(), std::io::Error> {
    let new_root = output_dir_buf.join("new");
    let old_root = output_dir_buf.join("old");
    create_dir_all(&new_root)?;
    create_dir_all(&old_root)?;

    let filtered_smali = |method: &SmaliMethod| -> String {
        let text = format!("{}", method);
        if filters.is_empty() {
            return text;
        }
        text.lines()
            .filter(|line| filters.iter().any(|r| r.is_match(line)))
            .collect::<Vec<_>>()
            .join("\n")
    };

    for (key, class) in &new_classes {
        let class_dir = key.replace(".", std::path::MAIN_SEPARATOR_STR);

        if let Some(old_class) = old_classes.get(key) {
            let old_methods: FxHashMap<String, &SmaliMethod> = old_class
                .methods
                .iter()
                .map(|m| (construct_java_signature(key.clone(), m), m))
                .collect();

            for new_method in &class.methods {
                let sig = construct_java_signature(key.clone(), new_method);

                match old_methods.get(&sig) {
                    Some(old_method) if !functions_match(old_method, new_method) => {
                        let old_dir = old_root.join(&class_dir);
                        let new_dir = new_root.join(&class_dir);
                        create_dir_all(&old_dir)?;
                        create_dir_all(&new_dir)?;

                        let fname = method_filename(new_method);
                        let mut f = File::create_new(new_dir.join(&fname))?;
                        write!(f, "{}", filtered_smali(new_method))?;

                        let fname = method_filename(old_method);
                        let mut f = File::create_new(old_dir.join(&fname))?;
                        write!(f, "{}", filtered_smali(old_method))?;
                    }
                    None => {
                        let new_dir = new_root.join(&class_dir);
                        create_dir_all(&new_dir)?;
                        let fname = method_filename(new_method);
                        let mut f = File::create_new(new_dir.join(&fname))?;
                        write!(f, "{}", filtered_smali(new_method))?;
                    }
                    _ => {}
                }
            }

            for old_method in &old_class.methods {
                let sig = construct_java_signature(key.clone(), old_method);
                if !class
                    .methods
                    .iter()
                    .any(|m| construct_java_signature(key.clone(), m) == sig)
                {
                    let old_dir = old_root.join(&class_dir);
                    create_dir_all(&old_dir)?;
                    let fname = method_filename(old_method);
                    let mut f = File::create_new(old_dir.join(&fname))?;
                    write!(f, "{}", filtered_smali(old_method))?;
                }
            }
        } else {
            let new_dir = new_root.join(&class_dir);
            for new_method in &class.methods {
                create_dir_all(&new_dir)?;
                let fname = method_filename(new_method);
                let mut f = File::create_new(new_dir.join(&fname))?;
                write!(f, "{}", filtered_smali(new_method))?;
            }
        }
    }
    Ok(())
}
/// Compare two sets of classes (keyed by Java type name) and return a list
/// of `EditType` values describing every change, addition, or removal at
/// the method-signature level.
pub fn find_changes_between_classes(
    new_classes: FxHashMap<String, SmaliClass>,
    old_classes: FxHashMap<String, SmaliClass>,
) -> Vec<EditType> {
    let mut res: Vec<EditType> = Vec::new();
    for (key, class) in &new_classes {
        if let Some(old_class) = old_classes.get(key) {
            let old_methods: FxHashMap<String, &SmaliMethod> = old_class
                .methods
                .iter()
                .map(|m| (construct_java_signature(key.clone(), m), m))
                .collect();
            for new_method in &class.methods {
                let sig = construct_java_signature(key.clone(), new_method);
                match old_methods.get(&sig) {
                    Some(old_method) => {
                        if !functions_match(old_method, new_method) {
                            res.push(EditType::Change(sig));
                        }
                    }
                    None => {
                        res.push(EditType::Addition(sig));
                    }
                }
            }
            for old_method in &old_class.methods {
                let sig = construct_java_signature(key.clone(), old_method);
                if !class
                    .methods
                    .iter()
                    .any(|m| construct_java_signature(key.clone(), m) == sig)
                {
                    res.push(EditType::Remove(sig));
                }
            }
        } else {
            for new_method in &class.methods {
                res.push(EditType::Addition(construct_java_signature(
                    key.clone(),
                    new_method,
                )));
            }
        }
    }
    res
}

/// Check whether two methods have the same sequence of `DexOp` discriminants
/// (ignoring operands).  A structural equality check for smali methods.
pub fn functions_match(old: &SmaliMethod, new: &SmaliMethod) -> bool {
    let old_ops: Vec<&DexOp> = old
        .ops
        .iter()
        .filter_map(|op| match op {
            SmaliOp::Op(d) => Some(d),
            _ => None,
        })
        .collect();
    let new_ops: Vec<&DexOp> = new
        .ops
        .iter()
        .filter_map(|op| match op {
            SmaliOp::Op(d) => Some(d),
            _ => None,
        })
        .collect();

    old_ops.len() == new_ops.len()
        && old_ops
            .iter()
            .zip(&new_ops)
            .all(|(a, b)| std::mem::discriminant(*a) == std::mem::discriminant(*b))
}

fn unpack_dex_file(dex: DexFile, filters: &[Regex], accum: &mut Vec<SmaliClass>) {
    if let Ok(classes) = dex.to_smali() {
        let tmpres: Vec<SmaliClass> = classes
            .into_par_iter()
            .filter(|val| {
                filters.is_empty()
                    || filters
                        .iter()
                        .any(|reg| reg.is_match(&val.name.as_java_type()))
            })
            .collect();
        accum.extend(tmpres);
    }
}

/// Read every DEX entry in an APK and return all `SmaliClass` values that
/// match the optional regex filters.
pub fn unpack_apk_classes(apk: &ApkFile, filters: &[Regex]) -> Vec<SmaliClass> {
    let entry_names: Vec<_> = apk.entry_names().filter(|x| is_top_level_dex_name(x)).collect();
    entry_names.par_iter()
        .fold(Vec::<SmaliClass>::new, |mut accum, x| {
            let entry_res = apk.entry(x);
            if let Some(entry) = entry_res {
                let dex_result = DexFile::from_bytes(&entry.data);
                if let Ok(dex) = dex_result {
                    unpack_dex_file(dex, filters, &mut accum);
                } else if let Err(e) = dex_result {
                    error!("Failed to create dex file from binary code provided by entry {x:?} due to reason: {e}");
                }
            };
            accum
        })
        .reduce(Vec::new, |mut accum, res| {
            accum.extend(res);
            accum
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use smali::smali_ops::{Label, MethodRef};
    use smali::types::MethodSignature;

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

    #[test]
    fn test_construct_java_signature_simple() {
        let m = make_method("foo", "()V", vec![]);
        let sig = construct_java_signature("com.example.Test".to_string(), &m);
        assert_eq!(sig, "com.example.Test: void foo([])");
    }

    #[test]
    fn test_construct_java_signature_with_args() {
        let m = make_method("bar", "(IZ)V", vec![]);
        let sig = construct_java_signature("com.example.Test".to_string(), &m);
        assert_eq!(sig, "com.example.Test: void bar([\"int\", \"boolean\"])");
    }

    #[test]
    fn test_construct_java_signature_with_result() {
        let m = make_method("getVal", "()I", vec![]);
        let sig = construct_java_signature("com.example.Test".to_string(), &m);
        assert_eq!(sig, "com.example.Test: int getVal([])");
    }

    #[test]
    fn test_functions_match_identical() {
        let ops = vec![SmaliOp::Op(DexOp::ReturnVoid)];
        let a = make_method("foo", "()V", ops.clone());
        let b = make_method("foo", "()V", ops);
        assert!(functions_match(&a, &b));
    }

    #[test]
    fn test_functions_match_different_op_count() {
        let a = make_method("foo", "()V", vec![SmaliOp::Op(DexOp::ReturnVoid)]);
        let b = make_method("foo", "()V", vec![]);
        assert!(!functions_match(&a, &b));
    }

    #[test]
    fn test_functions_match_different_ops() {
        let mref = MethodRef {
            class: "Lcom/example/Other;".to_string(),
            name: "helper".to_string(),
            descriptor: "()V".to_string(),
        };
        let a = make_method("foo", "()V", vec![SmaliOp::Op(DexOp::ReturnVoid)]);
        let b = make_method("foo", "()V", vec![
            SmaliOp::Op(DexOp::InvokeVirtual { registers: vec![], method: mref }),
        ]);
        assert!(!functions_match(&a, &b));
    }

    #[test]
    fn test_functions_match_different_operands_same_discriminant() {
        let a = make_method("foo", "()V", vec![
            SmaliOp::Op(DexOp::Goto { offset: Label("L1".to_string()) }),
        ]);
        let b = make_method("foo", "()V", vec![
            SmaliOp::Op(DexOp::Goto { offset: Label("L2".to_string()) }),
        ]);
        assert!(functions_match(&a, &b));
    }

    #[test]
    fn test_edit_type_display_change() {
        let e = EditType::Change("com.example.Test: void foo()".to_string());
        match e {
            EditType::Change(s) => assert_eq!(s, "com.example.Test: void foo()"),
            _ => panic!("expected Change"),
        }
    }

    #[test]
    fn test_edit_type_display_addition() {
        let e = EditType::Addition("com.example.Test: int bar()".to_string());
        match e {
            EditType::Addition(s) => assert_eq!(s, "com.example.Test: int bar()"),
            _ => panic!("expected Addition"),
        }
    }

    #[test]
    fn test_edit_type_display_remove() {
        let e = EditType::Remove("com.example.Test: void baz()".to_string());
        match e {
            EditType::Remove(s) => assert_eq!(s, "com.example.Test: void baz()"),
            _ => panic!("expected Remove"),
        }
    }
}
