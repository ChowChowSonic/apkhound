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

/// Check whether a candidate string is allowed by the given whitelist and blacklist regexes.
///
/// - Whitelist logic: If `whitelist` is non-empty, `val` must match at least one regex in `whitelist`.
///   If `whitelist` is empty, all candidates pass the whitelist.
/// - Blacklist logic: If `blacklist` is non-empty, `val` must NOT match any regex in `blacklist`.
///   If `blacklist` is empty, no candidates are rejected by the blacklist.
///
/// When both are supplied, `val` must satisfy the whitelist AND must not match any blacklist regex.
pub fn is_match_allowed(val: &str, whitelist: &[Regex], blacklist: &[Regex]) -> bool {
    let allowed_by_whitelist =
        whitelist.is_empty() || whitelist.iter().any(|reg| reg.is_match(val));
    let allowed_by_blacklist =
        blacklist.is_empty() || !blacklist.iter().any(|reg| reg.is_match(val));
    allowed_by_whitelist && allowed_by_blacklist
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

/// Extract all permission names from an `AndroidManifest`'s `uses-permission` tags.
pub fn extract_manifest_permission_names(manifest: &AndroidManifest) -> Vec<String> {
    manifest
        .uses_permissions()
        .iter()
        .filter_map(|p| {
            p.attribute_value("android:name")
                .or_else(|| p.attribute_value("name"))
                .and_then(|v| match v {
                    smali::android::binary_xml::ManifestValue::String(s) => Some(s.clone()),
                    _ => None,
                })
                .or_else(|| {
                    p.attributes
                        .iter()
                        .find(|attr| attr.name == "name" || attr.name == "android:name")
                        .and_then(|attr| attr.raw_value.clone())
                })
        })
        .collect()
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
        let old_attributes: Vec<String> = extract_manifest_permission_names(old_doc);
        let new_attributes: Vec<String> = extract_manifest_permission_names(new_doc);
        for x in &old_attributes {
            if !new_attributes.contains(x) && !res.0.contains(x) {
                res.0.push(x.clone());
            }
        }
        for y in &new_attributes {
            if !old_attributes.contains(y) && !res.1.contains(y) {
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
    fn test_extract_permissions_ignores_non_name_attributes() {
        let xml = r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
            <uses-permission android:name="android.permission.INTERNET" android:maxSdkVersion="28"/>
            <uses-permission android:name="android.permission.CAMERA"/>
        </manifest>"#;
        let manifest = AndroidManifest::from_string(xml).expect("parse manifest");
        let perms = extract_manifest_permission_names(&manifest);
        assert_eq!(
            perms,
            vec![
                "android.permission.INTERNET".to_string(),
                "android.permission.CAMERA".to_string()
            ]
        );
    }

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

    #[test]
    fn test_is_match_allowed_empty_filters() {
        let white: Vec<Regex> = vec![];
        let black: Vec<Regex> = vec![];
        assert!(is_match_allowed("com.example.Foo", &white, &black));
        assert!(is_match_allowed("android.app.Activity", &white, &black));
    }

    #[test]
    fn test_is_match_allowed_whitelist_only() {
        let white = build_regex(&["^com\\.example\\.".to_string()]);
        let black: Vec<Regex> = vec![];
        assert!(is_match_allowed("com.example.Foo", &white, &black));
        assert!(!is_match_allowed("com.other.Bar", &white, &black));
    }

    #[test]
    fn test_is_match_allowed_blacklist_only() {
        let white: Vec<Regex> = vec![];
        let black = build_regex(&["internal".to_string(), "generated".to_string()]);
        assert!(is_match_allowed("com.example.Foo", &white, &black));
        assert!(!is_match_allowed(
            "com.example.internal.Foo",
            &white,
            &black
        ));
        assert!(!is_match_allowed(
            "com.example.generated.Bar",
            &white,
            &black
        ));
    }

    #[test]
    fn test_is_match_allowed_whitelist_and_blacklist_combined() {
        let white = build_regex(&["^com\\.example\\.".to_string()]);
        let black = build_regex(&["internal".to_string()]);

        // Matches whitelist and does not match blacklist -> allowed
        assert!(is_match_allowed("com.example.PublicClass", &white, &black));
        // Matches whitelist but also matches blacklist -> blocked
        assert!(!is_match_allowed(
            "com.example.internal.Secret",
            &white,
            &black
        ));
        // Does not match whitelist -> blocked regardless of blacklist
        assert!(!is_match_allowed("org.other.PublicClass", &white, &black));
        assert!(!is_match_allowed(
            "org.other.internal.Secret",
            &white,
            &black
        ));
    }
}
