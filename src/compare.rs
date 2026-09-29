//! APK comparison logic — extract classes from two APKs, diff them at the
//! method-signature level, and optionally dump changed smali to disk.

use crate::matching::ClassMatchSet;
use rayon::prelude::*;
use regex::Regex;
use rustc_hash::FxHashMap;
use smali::android::zip::is_top_level_dex_name;
use smali::types::{SmaliClass, SmaliMethod, SmaliOp};
use smali::{android::zip::ApkFile, dex::DexFile};
use std::fs::{File, create_dir_all};
use std::hash::{Hash, Hasher};
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

/// Build a method signature relative to its class (return type, name, and arguments).
pub fn method_rel_signature(m: &SmaliMethod) -> String {
    let argslist: Vec<String> = m.signature.args.iter().map(|item| item.to_java()).collect();
    format!(
        "{} {}({:?})",
        m.signature.result.to_java(),
        m.name,
        argslist
    )
}

fn method_filename(m: &SmaliMethod) -> String {
    let safe_name = m.name.replace(['<', '>'], "");
    let args: Vec<String> = m.signature.args.iter().map(|t| t.to_java()).collect();
    let name = format!("{}({}).smali", safe_name, args.join(", "));
    if name.len() > 200 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        name.hash(&mut hasher);
        let hash = hasher.finish();
        format!("{}_{:016x}.smali", safe_name, hash)
    } else {
        name
    }
}

/// For each changed / added / removed method, write the old and new smali to
/// `output_dir/{old,new}/...`. An optional list of `filters` restricts
/// which smali lines are written. When `match_set` is provided, paired classes
/// are compared across obfuscated boundaries.
pub fn dump_changes_between_classes(
    new_classes: FxHashMap<String, SmaliClass>,
    old_classes: FxHashMap<String, SmaliClass>,
    output_dir_buf: &Path,
    filters: &[Regex],
    match_set: Option<&ClassMatchSet>,
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

    if let Some(ms) = match_set {
        for (new_key, class) in &new_classes {
            let new_class_dir = new_key.replace(".", std::path::MAIN_SEPARATOR_STR);
            let old_key_opt = ms.new_to_old.get(new_key).or_else(|| {
                if old_classes.contains_key(new_key) {
                    Some(new_key)
                } else {
                    None
                }
            });

            if let Some(old_key) = old_key_opt
                && let Some(old_class) = old_classes.get(old_key)
            {
                let old_class_dir = old_key.replace(".", std::path::MAIN_SEPARATOR_STR);
                let old_methods: FxHashMap<String, &SmaliMethod> = old_class
                    .methods
                    .iter()
                    .map(|m| (method_rel_signature(m), m))
                    .collect();

                for new_method in &class.methods {
                    let rel_sig = method_rel_signature(new_method);
                    match old_methods.get(&rel_sig) {
                        Some(old_method) if !functions_match(old_method, new_method) => {
                            let old_dir = old_root.join(&old_class_dir);
                            let new_dir = new_root.join(&new_class_dir);
                            create_dir_all(&old_dir)?;
                            create_dir_all(&new_dir)?;

                            let fname = method_filename(new_method);
                            let mut f = File::create(new_dir.join(&fname))?;
                            write!(f, "{}", filtered_smali(new_method))?;

                            let fname = method_filename(old_method);
                            let mut f = File::create(old_dir.join(&fname))?;
                            write!(f, "{}", filtered_smali(old_method))?;
                        }
                        None => {
                            let new_dir = new_root.join(&new_class_dir);
                            create_dir_all(&new_dir)?;
                            let fname = method_filename(new_method);
                            let mut f = File::create(new_dir.join(&fname))?;
                            write!(f, "{}", filtered_smali(new_method))?;
                        }
                        _ => {}
                    }
                }

                for old_method in &old_class.methods {
                    let rel_sig = method_rel_signature(old_method);
                    if !class
                        .methods
                        .iter()
                        .any(|m| method_rel_signature(m) == rel_sig)
                    {
                        let old_dir = old_root.join(&old_class_dir);
                        create_dir_all(&old_dir)?;
                        let fname = method_filename(old_method);
                        let mut f = File::create(old_dir.join(&fname))?;
                        write!(f, "{}", filtered_smali(old_method))?;
                    }
                }
            } else {
                let new_dir = new_root.join(&new_class_dir);
                for new_method in &class.methods {
                    create_dir_all(&new_dir)?;
                    let fname = method_filename(new_method);
                    let mut f = File::create(new_dir.join(&fname))?;
                    write!(f, "{}", filtered_smali(new_method))?;
                }
            }
        }

        for (old_key, old_class) in &old_classes {
            let is_paired = ms
                .old_to_new
                .get(old_key)
                .is_some_and(|nk| new_classes.contains_key(nk))
                || new_classes.contains_key(old_key);
            if !is_paired {
                let class_dir = old_key.replace(".", std::path::MAIN_SEPARATOR_STR);
                let old_dir = old_root.join(&class_dir);
                for old_method in &old_class.methods {
                    create_dir_all(&old_dir)?;
                    let fname = method_filename(old_method);
                    let mut f = File::create(old_dir.join(&fname))?;
                    write!(f, "{}", filtered_smali(old_method))?;
                }
            }
        }
    } else {
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
                            let mut f = File::create(new_dir.join(&fname))?;
                            write!(f, "{}", filtered_smali(new_method))?;

                            let fname = method_filename(old_method);
                            let mut f = File::create(old_dir.join(&fname))?;
                            write!(f, "{}", filtered_smali(old_method))?;
                        }
                        None => {
                            let new_dir = new_root.join(&class_dir);
                            create_dir_all(&new_dir)?;
                            let fname = method_filename(new_method);
                            let mut f = File::create(new_dir.join(&fname))?;
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
                        let mut f = File::create(old_dir.join(&fname))?;
                        write!(f, "{}", filtered_smali(old_method))?;
                    }
                }
            } else {
                let new_dir = new_root.join(&class_dir);
                for new_method in &class.methods {
                    create_dir_all(&new_dir)?;
                    let fname = method_filename(new_method);
                    let mut f = File::create(new_dir.join(&fname))?;
                    write!(f, "{}", filtered_smali(new_method))?;
                }
            }
        }
        for (key, old_class) in &old_classes {
            if !new_classes.contains_key(key) {
                let class_dir = key.replace(".", std::path::MAIN_SEPARATOR_STR);
                let old_dir = old_root.join(&class_dir);
                for old_method in &old_class.methods {
                    create_dir_all(&old_dir)?;
                    let fname = method_filename(old_method);
                    let mut f = File::create(old_dir.join(&fname))?;
                    write!(f, "{}", filtered_smali(old_method))?;
                }
            }
        }
    }
    Ok(())
}

/// Compare two sets of classes (keyed by Java type name) and return a list
/// of `EditType` values describing every change, addition, or removal at
/// the method-signature level. When `match_set` is provided, paired classes
/// are compared across obfuscated boundaries.
pub fn find_changes_between_classes(
    new_classes: FxHashMap<String, SmaliClass>,
    old_classes: FxHashMap<String, SmaliClass>,
    match_set: Option<&ClassMatchSet>,
) -> Vec<EditType> {
    let mut res: Vec<EditType> = Vec::new();

    if let Some(ms) = match_set {
        for (new_key, class) in &new_classes {
            let old_key_opt = ms.new_to_old.get(new_key).or_else(|| {
                if old_classes.contains_key(new_key) {
                    Some(new_key)
                } else {
                    None
                }
            });

            if let Some(old_key) = old_key_opt
                && let Some(old_class) = old_classes.get(old_key)
            {
                let old_methods: FxHashMap<String, &SmaliMethod> = old_class
                    .methods
                    .iter()
                    .map(|m| (method_rel_signature(m), m))
                    .collect();
                for new_method in &class.methods {
                    let rel_sig = method_rel_signature(new_method);
                    let sig = construct_java_signature(new_key.clone(), new_method);
                    match old_methods.get(&rel_sig) {
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
                    let rel_sig = method_rel_signature(old_method);
                    if !class
                        .methods
                        .iter()
                        .any(|m| method_rel_signature(m) == rel_sig)
                    {
                        res.push(EditType::Remove(construct_java_signature(
                            old_key.clone(),
                            old_method,
                        )));
                    }
                }
            } else {
                for new_method in &class.methods {
                    res.push(EditType::Addition(construct_java_signature(
                        new_key.clone(),
                        new_method,
                    )));
                }
            }
        }
        for (old_key, old_class) in &old_classes {
            let is_paired = ms
                .old_to_new
                .get(old_key)
                .is_some_and(|nk| new_classes.contains_key(nk))
                || new_classes.contains_key(old_key);
            if !is_paired {
                for old_method in &old_class.methods {
                    res.push(EditType::Remove(construct_java_signature(
                        old_key.clone(),
                        old_method,
                    )));
                }
            }
        }
    } else {
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
        for (key, old_class) in &old_classes {
            if !new_classes.contains_key(key) {
                for old_method in &old_class.methods {
                    res.push(EditType::Remove(construct_java_signature(
                        key.clone(),
                        old_method,
                    )));
                }
            }
        }
    }
    res
}

/// Check whether two methods have the same sequence of `DexOp` discriminants
/// (ignoring operands).  A structural equality check for smali methods.
pub fn functions_match(old: &SmaliMethod, new: &SmaliMethod) -> bool {
    if old.ops.len() != new.ops.len() {
        return false;
    }
    old.ops
        .iter()
        .zip(new.ops.iter())
        .all(|(a, b)| match (a, b) {
            (SmaliOp::Op(a), SmaliOp::Op(b)) => {
                std::mem::discriminant(a) == std::mem::discriminant(b)
            }
            _ => std::mem::discriminant(a) == std::mem::discriminant(b),
        })
}

/// Check whether two methods have matching headers (modifiers, constructor flag,
/// registers, locals, signature, parameters, and annotations).
pub fn method_headers_match(old: &SmaliMethod, new: &SmaliMethod) -> bool {
    if old.constructor != new.constructor
        || old.registers != new.registers
        || old.locals != new.locals
        || old.signature.to_jni() != new.signature.to_jni()
    {
        return false;
    }

    let mut old_mods: Vec<_> = old.modifiers.iter().map(|m| m.to_str()).collect();
    old_mods.sort_unstable();
    let mut new_mods: Vec<_> = new.modifiers.iter().map(|m| m.to_str()).collect();
    new_mods.sort_unstable();
    if old_mods != new_mods {
        return false;
    }

    if old.params.len() != new.params.len()
        || format!("{:?}", old.params) != format!("{:?}", new.params)
    {
        return false;
    }

    if old.annotations.len() != new.annotations.len()
        || format!("{:?}", old.annotations) != format!("{:?}", new.annotations)
    {
        return false;
    }

    true
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
    let entry_names: Vec<_> = apk
        .entry_names()
        .filter(|x| is_top_level_dex_name(x))
        .collect();
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
    use smali::smali_ops::{DexOp, Label, MethodRef};
    use smali::types::{MethodSignature, Modifier};

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
        let b = make_method(
            "foo",
            "()V",
            vec![SmaliOp::Op(DexOp::InvokeVirtual {
                registers: vec![],
                method: mref,
            })],
        );
        assert!(!functions_match(&a, &b));
    }

    #[test]
    fn test_functions_match_different_operands_same_discriminant() {
        let a = make_method(
            "foo",
            "()V",
            vec![SmaliOp::Op(DexOp::Goto {
                offset: Label("L1".to_string()),
            })],
        );
        let b = make_method(
            "foo",
            "()V",
            vec![SmaliOp::Op(DexOp::Goto {
                offset: Label("L2".to_string()),
            })],
        );
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

    #[test]
    fn test_functions_match_different_label_count() {
        let a = make_method(
            "foo",
            "()V",
            vec![
                SmaliOp::Label(Label("L1".to_string())),
                SmaliOp::Op(DexOp::ReturnVoid),
            ],
        );
        let b = make_method("foo", "()V", vec![SmaliOp::Op(DexOp::ReturnVoid)]);
        assert!(!functions_match(&a, &b));
    }

    #[test]
    fn test_functions_match_different_debug_presence() {
        let a = make_method(
            "foo",
            "()V",
            vec![SmaliOp::Prologue, SmaliOp::Op(DexOp::ReturnVoid)],
        );
        let b = make_method("foo", "()V", vec![SmaliOp::Op(DexOp::ReturnVoid)]);
        assert!(!functions_match(&a, &b));
    }

    #[test]
    fn test_functions_match_same_non_op_ops() {
        let a = make_method(
            "foo",
            "()V",
            vec![
                SmaliOp::Prologue,
                SmaliOp::Op(DexOp::ReturnVoid),
                SmaliOp::Epilogue,
            ],
        );
        let b = make_method(
            "foo",
            "()V",
            vec![
                SmaliOp::Prologue,
                SmaliOp::Op(DexOp::ReturnVoid),
                SmaliOp::Epilogue,
            ],
        );
        assert!(functions_match(&a, &b));
    }

    #[test]
    fn test_method_filename_short() {
        let m = make_method("foo", "()V", vec![]);
        let name = method_filename(&m);
        assert_eq!(name, "foo().smali");
    }

    #[test]
    fn test_method_filename_long_signature_truncated() {
        let long_jni = format!(
            "(L{desc};L{desc};L{desc};L{desc};L{desc};L{desc};L{desc};L{desc};L{desc};L{desc};)V",
            desc = "android/content/ContentProviderClient"
        );
        let m = make_method("veryLongMethod", &long_jni, vec![]);
        let name = method_filename(&m);
        assert!(name.len() < 255, "filename length: {}", name.len());
        assert!(
            name.starts_with("veryLongMethod_"),
            "expected hash suffix, got: {name}"
        );
        assert!(name.ends_with(".smali"));
    }

    #[test]
    fn test_method_filename_same_name_different_sigs_different_hash() {
        let m1 = make_method("foo", "(I)V", vec![]);
        let m2 = make_method("foo", "(J)V", vec![]);
        let n1 = method_filename(&m1);
        let n2 = method_filename(&m2);
        if n1.len() > 200 {
            assert_ne!(
                n1, n2,
                "different signatures should produce different hashed names"
            );
        }
    }

    #[test]
    fn test_find_changes_with_match_set() {
        use smali::types::ObjectIdentifier;

        let make_class = |name: &str, methods: Vec<SmaliMethod>| SmaliClass {
            name: ObjectIdentifier::from_java_type(name),
            modifiers: vec![],
            source: None,
            super_class: ObjectIdentifier::from_java_type("java.lang.Object"),
            implements: vec![],
            annotations: vec![],
            fields: vec![],
            methods,
            file_path: None,
        };

        let old_m = make_method("run", "()V", vec![SmaliOp::Op(DexOp::ReturnVoid)]);
        let new_m = make_method(
            "run",
            "()V",
            vec![SmaliOp::Op(DexOp::Nop), SmaliOp::Op(DexOp::ReturnVoid)],
        );

        let old_cls = make_class("com.example.OldClass", vec![old_m]);
        let new_cls = make_class("a.b.c", vec![new_m]);

        let mut old_map = FxHashMap::default();
        old_map.insert("com.example.OldClass".to_string(), old_cls);

        let mut new_map = FxHashMap::default();
        new_map.insert("a.b.c".to_string(), new_cls);

        // Without match_set: 1 removed, 1 added
        let edits_no_match = find_changes_between_classes(new_map.clone(), old_map.clone(), None);
        assert_eq!(edits_no_match.len(), 2);
        assert!(
            edits_no_match
                .iter()
                .any(|e| matches!(e, EditType::Remove(_)))
        );
        assert!(
            edits_no_match
                .iter()
                .any(|e| matches!(e, EditType::Addition(_)))
        );

        // With match_set: 1 changed!
        let mut match_set = ClassMatchSet::default();
        match_set.insert("com.example.OldClass".to_string(), "a.b.c".to_string(), 0.9);

        let edits_with_match = find_changes_between_classes(new_map, old_map, Some(&match_set));
        assert_eq!(edits_with_match.len(), 1);
        assert!(
            edits_with_match
                .iter()
                .any(|e| matches!(e, EditType::Change(_)))
        );
    }

    #[test]
    fn test_method_headers_match_identical() {
        let a = make_method("foo", "()V", vec![]);
        let b = make_method("foo", "()V", vec![]);
        assert!(method_headers_match(&a, &b));
    }

    #[test]
    fn test_method_headers_match_different_modifiers() {
        let mut a = make_method("foo", "()V", vec![]);
        a.modifiers = vec![Modifier::Public];
        let mut b = make_method("foo", "()V", vec![]);
        b.modifiers = vec![Modifier::Private];
        assert!(!method_headers_match(&a, &b));

        // Order independence
        let mut c = make_method("foo", "()V", vec![]);
        c.modifiers = vec![Modifier::Static, Modifier::Public];
        let mut d = make_method("foo", "()V", vec![]);
        d.modifiers = vec![Modifier::Public, Modifier::Static];
        assert!(method_headers_match(&c, &d));
    }

    #[test]
    fn test_method_headers_match_different_constructor() {
        let mut a = make_method("foo", "()V", vec![]);
        a.constructor = true;
        let b = make_method("foo", "()V", vec![]);
        assert!(!method_headers_match(&a, &b));
    }

    #[test]
    fn test_method_headers_match_different_registers() {
        let mut a = make_method("foo", "()V", vec![]);
        a.registers = Some(4);
        let mut b = make_method("foo", "()V", vec![]);
        b.registers = Some(8);
        assert!(!method_headers_match(&a, &b));
    }
}
