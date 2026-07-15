use rayon::prelude::*;
use regex::Regex;
use smali::android::zip::is_top_level_dex_name;
use smali::smali_ops::DexOp;
use smali::types::SmaliMethod;
use smali::{android::zip::ApkFile, dex::DexFile, types::SmaliClass, types::SmaliOp};
use std::collections::HashMap;
use std::fs::{File, create_dir_all};
use std::io::prelude::*;
use std::path::PathBuf;
use tracing::error;

pub enum EditType {
    Change(String),
    Remove(String),
    Addition(String),
}

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
    let safe_name = m.name.replace('<', "").replace('>', "");
    let args: Vec<String> = m.signature.args.iter().map(|t| t.to_java()).collect();
    format!("{}({}).smali", safe_name, args.join(", "))
}

pub fn dump_changes_between_classes(
    new_classes: HashMap<String, SmaliClass>,
    old_classes: HashMap<String, SmaliClass>,
    output_dir_buf: &PathBuf,
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
            let old_methods: HashMap<String, &SmaliMethod> = old_class
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
pub fn find_changes_between_classes(
    new_classes: HashMap<String, SmaliClass>,
    old_classes: HashMap<String, SmaliClass>,
) -> Vec<EditType> {
    let mut res: Vec<EditType> = Vec::new();
    for (key, class) in &new_classes {
        if let Some(old_class) = old_classes.get(key) {
            let old_methods: HashMap<String, &SmaliMethod> = old_class
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

pub fn unpack_apk_classes(apk: &ApkFile, filters: &[Regex]) -> Vec<SmaliClass> {
    apk.entry_names().filter(|x| is_top_level_dex_name(x))
        .par_bridge()
        .into_par_iter()
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
