//! Handler for the `extract` subcommand — dumps changed method smali to a
//! directory structure.

use crate::compare::{dump_changes_between_classes, unpack_apk_classes};
use crate::matching::{MatchParams, build_class_match_set};
use crate::utils::build_regex;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use rustc_hash::FxHashMap;
use smali::android::zip::ApkFile;
use smali::types::SmaliClass;
use std::path::PathBuf;
use tracing::error;

/// Unpack both APKs, diff their classes, and write the smali of every
/// changed / added / removed method into `output_dir/{old,new}/...`.
/// Class and smali-line filters can further narrow what is written.
/// When `match_obfuscated` is true, runs matching analysis first to pair
/// classes across obfuscated names.
pub fn handle_extract(
    old_apk: PathBuf,
    new_apk: PathBuf,
    output_dir: PathBuf,
    class_filters: Vec<String>,
    smali_filters: Vec<String>,
    match_obfuscated: bool,
) -> Result<(), String> {
    let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
        .par_iter()
        .map(ApkFile::from_file)
        .collect();
    match (&apks[0], &apks[1]) {
        (Ok(old), Ok(new)) => {
            let regex: Vec<Regex> = build_regex(&class_filters);
            let smali_regex: Vec<Regex> = build_regex(&smali_filters);
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
            dump_changes_between_classes(
                new_classes,
                old_classes,
                &output_dir,
                &smali_regex,
                match_set.as_ref(),
            )
            .map_err(|e| format!("Failed to write extracted smali files: {e}"))?;
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
