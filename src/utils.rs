use regex::Regex;
use smali::android::binary_xml::AndroidManifest;
use smali::android::zip::ApkFile;
use std::str::FromStr;
use tracing::error;

pub fn build_regex(filters: &[String]) -> Vec<Regex> {
    let mut regex: Vec<Regex> = Vec::new();
    for x in filters {
        let regex_val = Regex::from_str(x);
        if let Ok(r) = regex_val {
            regex.push(r);
        } else if let Err(e) = regex_val {
            error!("Failed to parse regex {x:?} due to reason: {e}");
        }
    }
    regex
}

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

pub fn compare_manifest_permissions(old: &ApkFile, new: &ApkFile) -> (Vec<String>, Vec<String>) {
    let mut res: (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let old_manifest_res = extract_manifest(old);
    let new_manifest_res = extract_manifest(new);
    if let Ok(old_doc) = &old_manifest_res
        && let Ok(new_doc) = &new_manifest_res
    {
        let old_permissions = old_doc.uses_permissions();
        let new_permissions = new_doc.uses_permissions();
        let mut old_attributes: Vec<String> = Vec::new();
        let mut new_attributes: Vec<String> = Vec::new();
        for (x, a) in old_permissions.iter().zip(&new_permissions) {
            for y in x.attributes.iter().filter_map(|t| t.raw_value.clone()) {
                old_attributes.push(y);
            }
            for y in a.attributes.iter().filter_map(|t| t.raw_value.clone()) {
                new_attributes.push(y);
            }
        }
        for (x, y) in old_attributes.iter().zip(&new_attributes) {
            if !new_attributes.contains(x) {
                //println!("PERMISSION REMOVED: {}", x);
                res.0.push(x.into());
            }
            if !old_attributes.contains(y) {
                //println!("PERMISSION ADDED: {}", y);
                res.1.push(y.into());
            }
        }
    } else if let Err(old) = old_manifest_res {
        error!("Error parsing old AndroidManifest: {old}");
    } else if let Err(new) = new_manifest_res {
        error!("Error parsing new AndroidManifest: {new}");
    }
    res
}
