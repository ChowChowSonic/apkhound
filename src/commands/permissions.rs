//! Handler for the `permissions` subcommand — lists or diffs Android
//! manifest permissions between APKs.

use crate::utils::{compare_manifest_permissions, extract_manifest};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use smali::android::zip::ApkFile;
use std::path::PathBuf;
use tracing::error;

/// If `new_apk` is provided, diff the permissions between both APKs and
/// print added / deleted permissions.  Otherwise print every
/// `uses-permission` from the single APK.
pub fn handle_permissions(old_apk: PathBuf, new_apk: Option<PathBuf>) -> Result<(), String> {
    if let Some(new_res) = new_apk {
        let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_res]
            .par_iter()
            .map(ApkFile::from_file)
            .collect();
        match (&apks[0], &apks[1]) {
            (Ok(old), Ok(new)) => {
                let (deleted, added) = compare_manifest_permissions(old, new);
                for x in deleted {
                    println!("DELETED: {x}");
                }

                for x in added {
                    println!("ADDED: {x}");
                }
                Ok(())
            }
            (Err(old), _) => {
                error!("Unable to parse old APK due to reason: {old}");
                Err(format!("Error parsing old apk: {old}"))
            }
            (_, Err(new)) => {
                error!("Unable to parse new APK due to reason: {new}");
                Err(format!("Error parsing new apk: {new}"))
            }
        }
    } else {
        match ApkFile::from_file(old_apk) {
            Ok(apk) => {
                let manifest = extract_manifest(&apk).map_err(|e| {
                    error!("Unable to extract manifest due to reason: {e}");
                    format!("Unable to extract manifest due to reason: {e}")
                })?;
                for x in manifest.uses_permissions() {
                    for y in x.attributes.iter().filter_map(|t| t.raw_value.clone()) {
                        println!("{y}");
                    }
                }
                Ok(())
            }
            Err(e) => {
                error!("Unable to open APK due to reason: {e}");
                Err(format!("Unable to open APK due to reason: {e}"))
            }
        }
    }
}
