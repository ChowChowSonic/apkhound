use smali::android::binary_xml::AndroidManifest;
use smali::android::zip::ApkFile;
use tracing::error;
pub fn extract_manifest(apk: &ApkFile) -> Result<AndroidManifest, String> {
    let manifest_entry_res = apk.entry("AndroidManifest.xml");

    if let Some(manifest_entry) = manifest_entry_res {
        let doc_res = AndroidManifest::from_apk_entry(manifest_entry);
        match doc_res {
            Ok(doc) => Ok(doc),
            Err(e) => {
                error!("Unable to parse binary XML from AndroidManifest due to reason: {e}");
                Err(e.to_string())
            }
        }
    } else {
        error!("Error retrieving AndroidManifest.xml from APK: No Manifest found");
        Err("Error retrieving AndroidManifest.xml from APK: No Manifest found".to_string())
    }
}
