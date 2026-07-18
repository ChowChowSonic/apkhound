//! Handler for the `compare` subcommand — diffs two APKs at the
//! method-signature level and prints added / removed / changed methods.

use crate::compare::{EditType, find_changes_between_classes, unpack_apk_classes};
use crate::utils::build_regex;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use rustc_hash::FxHashMap;
use smali::android::zip::ApkFile;
use smali::types::SmaliClass;
use std::path::PathBuf;
use tracing::error;

/// Compare the classes in `old_apk` and `new_apk` and print any additions,
/// removals, or changes found.  An optional list of regex `filters` can
/// restrict which classes are examined.
pub fn handle_compare(
    old_apk: PathBuf,
    new_apk: PathBuf,
    filters: Vec<String>,
) -> Result<(), String> {
    let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
        .par_iter()
        .map(ApkFile::from_file)
        .collect();
    match (&apks[0], &apks[1]) {
        (Ok(old), Ok(new)) => {
            let regex: Vec<Regex> = build_regex(&filters);
            let old_classes = unpack_apk_classes(old, &regex)
                .par_iter()
                .fold(
                    FxHashMap::<String, SmaliClass>::default,
                    |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    },
                )
                .reduce(FxHashMap::default, |mut accum, mut res| {
                    accum.extend(res.drain());
                    accum
                });
            let new_classes = unpack_apk_classes(new, &regex)
                .par_iter()
                .fold(
                    FxHashMap::<String, SmaliClass>::default,
                    |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    },
                )
                .reduce(FxHashMap::default, |mut accum, mut res| {
                    accum.extend(res.drain());
                    accum
                });
            let res = find_changes_between_classes(new_classes, old_classes);
            for x in res {
                match x {
                    EditType::Change(x) => println!("CHANGED: {x}"),
                    EditType::Addition(x) => println!("ADDED: {x}"),
                    EditType::Remove(x) => println!("REMOVED: {x}"),
                }
            }
            Ok(())
        }
        (Err(old), _) => {
            error!("Error parsing old apk: {old}");
            Err(format!("Error parsing old apk: {old}"))
        }
        (_, Err(new)) => {
            error!("Error parsing new apk: {new}");
            Err(format!("Error parsing new apk: {new}"))
        }
    }
}
