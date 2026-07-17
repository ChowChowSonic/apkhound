use crate::compare::{unpack_apk_classes, dump_changes_between_classes};
use crate::utils::build_regex;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use smali::android::zip::ApkFile;
use smali::types::SmaliClass;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::error;

pub fn handle_extract(
    old_apk: PathBuf,
    new_apk: PathBuf,
    output_dir: PathBuf,
    class_filters: Vec<String>,
    smali_filters: Vec<String>,
) {
    let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
        .par_iter()
        .map(ApkFile::from_file)
        .collect();
    if let Ok(new) = &apks[1]
        && let Ok(old) = &apks[0]
    {
        let regex: Vec<Regex> = build_regex(&class_filters);
        let smali_regex: Vec<Regex> = build_regex(&smali_filters);
        let old_classes = unpack_apk_classes(old, &regex)
            .par_iter()
            .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                accum.insert(item.name.as_java_type(), item.clone());
                accum
            })
            .reduce(HashMap::new, |mut accum, mut res| {
                accum.extend(res.drain());
                accum
            });
        let new_classes = unpack_apk_classes(new, &regex)
            .par_iter()
            .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                accum.insert(item.name.as_java_type(), item.clone());
                accum
            })
            .reduce(HashMap::new, |mut accum, mut res| {
                accum.extend(res.drain());
                accum
            });
        let _ = dump_changes_between_classes(new_classes, old_classes, &output_dir, &smali_regex);
    } else if let Err(old) = &apks[0] {
        error!("Error parsing old apk: {old}");
    } else if let Err(new) = &apks[1] {
        error!("Error parsing new apk: {new}");
    }
}
