//! Handler for the `compare` subcommand — diffs two APKs at the
//! method-signature level and prints added / removed / changed methods.

use crate::compare::{EditType, find_changes_between_classes, unpack_apk_classes};
use crate::matching::{MatchParams, build_class_match_set};
use crate::utils::build_regex;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use rustc_hash::FxHashMap;
use smali::android::zip::ApkFile;
use smali::types::SmaliClass;
use std::path::PathBuf;
use tracing::error;

/// Compare the classes in `old_apk` and `new_apk` and print any additions,
/// removals, or changes found. An optional list of regex `filters` can
/// restrict which classes are examined. When `match_obfuscated` is true,
/// runs matching analysis first to pair classes across obfuscated names.
pub fn handle_compare(
    old_apk: PathBuf,
    new_apk: PathBuf,
    filters: Vec<String>,
    match_obfuscated: bool,
) -> Result<(), String> {
    let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
        .par_iter()
        .map(ApkFile::from_file)
        .collect();
    match (&apks[0], &apks[1]) {
        (Ok(old), Ok(new)) => {
            let regex: Vec<Regex> = build_regex(&filters);
            let old_classes_vec = unpack_apk_classes(old, &regex);
            let new_classes_vec = unpack_apk_classes(new, &regex);

            let match_set = if match_obfuscated {
                let params = MatchParams::default();
                Some(build_class_match_set(
                    &old_classes_vec,
                    &new_classes_vec,
                    &params,
                ))
            } else {
                None
            };

            let old_classes: FxHashMap<String, SmaliClass> = old_classes_vec
                .into_iter()
                .map(|item| (item.name.as_java_type(), item))
                .collect();
            let new_classes: FxHashMap<String, SmaliClass> = new_classes_vec
                .into_iter()
                .map(|item| (item.name.as_java_type(), item))
                .collect();
            let res = find_changes_between_classes(new_classes, old_classes, match_set.as_ref());
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
