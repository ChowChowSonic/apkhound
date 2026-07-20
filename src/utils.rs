//! Shared utility functions used across command handlers.

use regex::Regex;
use smali::android::binary_xml::AndroidManifest;
use smali::android::zip::ApkFile;
use std::str::FromStr;
use tracing::error;

/// Compile a list of regex strings into `Regex` values, logging errors for
/// any that fail to parse.
pub fn build_regex(filters: &[String]) -> Vec<Regex> {
    let mut regex: Vec<Regex> = Vec::new();
    for x in filters {
        let regex_val = Regex::from_str(x);
        if let Ok(r) = regex_val {
            regex.push(r);
        } else if let Err(e) = regex_val {
            error!("Failed to parse regex {x:?} due to reason: {e}");
            panic!("Failed to parse regex");
        }
    }
    regex
}

/// Read the binary `AndroidManifest.xml` from an APK and parse it into an
/// `AndroidManifest` value.
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

/// Diff the `uses-permission` entries between two APKs.
/// Returns `(deleted, added)` permission name lists.
pub fn compare_manifest_permissions(old: &ApkFile, new: &ApkFile) -> (Vec<String>, Vec<String>) {
    let mut res: (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let old_manifest_res = extract_manifest(old);
    let new_manifest_res = extract_manifest(new);
    if let Ok(old_doc) = &old_manifest_res
        && let Ok(new_doc) = &new_manifest_res
    {
        let old_attributes: Vec<String> = old_doc
            .uses_permissions()
            .iter()
            .flat_map(|x| x.attributes.iter().filter_map(|t| t.raw_value.clone()))
            .collect();
        let new_attributes: Vec<String> = new_doc
            .uses_permissions()
            .iter()
            .flat_map(|x| x.attributes.iter().filter_map(|t| t.raw_value.clone()))
            .collect();
        for x in &old_attributes {
            if !new_attributes.contains(x) {
                res.0.push(x.clone());
            }
        }
        for y in &new_attributes {
            if !old_attributes.contains(y) {
                res.1.push(y.clone());
            }
        }
    } else {
        if let Err(old) = &old_manifest_res {
            error!("Error parsing old AndroidManifest: {old}");
        }
        if let Err(new) = &new_manifest_res {
            error!("Error parsing new AndroidManifest: {new}");
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_regex_empty() {
        let filters: Vec<String> = vec![];
        let regexes = build_regex(&filters);
        assert!(regexes.is_empty());
    }

    #[test]
    fn test_build_regex_valid() {
        let filters = vec!["^com\\.example".to_string(), "android\\.app".to_string()];
        let regexes = build_regex(&filters);
        assert_eq!(regexes.len(), 2);
        assert!(regexes[0].is_match("com.example.Test"));
        assert!(regexes[1].is_match("android.app.Activity"));
        assert!(!regexes[1].is_match("com.example.Test"));
    }

    #[test]
    #[should_panic]
    fn test_build_regex_invalid_fails() {
        let filters = vec![
            "^com\\.example".to_string(),
            "[invalid".to_string(),
            "android".to_string(),
        ];
        let regexes = build_regex(&filters);
        assert_eq!(regexes.len(), 2); // invalid one skipped
    }

    #[test]
    fn test_build_regex_empty_string() {
        let filters = vec!["".to_string()];
        let regexes = build_regex(&filters);
        assert_eq!(regexes.len(), 1);
        // empty regex matches everything
    }
}
