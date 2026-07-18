//! Handler for the `extract` subcommand — dumps changed method smali to a
//! directory structure.

use crate::compare::{dump_changes_between_classes, unpack_apk_classes};
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
pub fn handle_extract(
    old_apk: PathBuf,
    new_apk: PathBuf,
    output_dir: PathBuf,
    class_filters: Vec<String>,
    smali_filters: Vec<String>,
) -> Result<(), String> {
    let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
        .par_iter()
        .map(ApkFile::from_file)
        .collect();
    match (&apks[0], &apks[1]) {
        (Ok(old), Ok(new)) => {
            let regex: Vec<Regex> = build_regex(&class_filters);
            let smali_regex: Vec<Regex> = build_regex(&smali_filters);
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
                .reduce(
                    FxHashMap::<String, SmaliClass>::default,
                    |mut accum, mut res| {
                        accum.extend(res.drain());
                        accum
                    },
                );
            let _ = dump_changes_between_classes(new_classes, old_classes, &output_dir, &smali_regex);
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
