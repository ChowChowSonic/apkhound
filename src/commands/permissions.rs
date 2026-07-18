//! Handler for the `permissions` subcommand — lists or diffs Android
//! manifest permissions between APKs.

use crate::utils::{compare_manifest_permissions, extract_manifest};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use smali::android::binary_xml::AndroidManifest;
use smali::android::zip::ApkFile;
use std::path::PathBuf;
use tracing::error;

/// If `new_apk` is provided, diff the permissions between both APKs and
/// print added / deleted permissions.  Otherwise print every
/// `uses-permission` from the single APK.
pub fn handle_permissions(
    old_apk: PathBuf,
    new_apk: Option<PathBuf>,
) -> Result<(), ()> {
    if let Some(new_res) = new_apk {
        let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_res]
            .par_iter()
            .map(ApkFile::from_file)
            .collect();
        if let Ok(old) = &apks[0]
            && let Ok(new) = &apks[1]
        {
            let (deleted, added) = compare_manifest_permissions(old, new);
            for x in deleted {
                println!("DELETED: {x}");
            }

            for x in added {
                println!("ADDED: {x}");
            }
            Ok(())
        } else {
            if let Err(old) = &apks[0] {
                error!("Unable to parse old APK due to reason: {old}");
            }
            if let Err(new) = &apks[1] {
                error!("Unable to parse new APK due to reason: {new}");
            }
            Err(())
        }
    } else if let Ok(apk) = ApkFile::from_file(old_apk) {
        let manifest: AndroidManifest =
            extract_manifest(&apk).expect("Error when trying to retrieve android manifest");
        for x in manifest.uses_permissions() {
            for y in x.attributes.iter().filter_map(|t| t.raw_value.clone()) {
                println!("{y:?}");
            }
        }
        Ok(())
    } else {
        Err(())
    }
}
