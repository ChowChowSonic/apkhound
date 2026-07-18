//! Handler for the `manifest` subcommand — extracts and displays
//! `AndroidManifest.xml` in one of four formats.

use crate::manifest_summary::ManifestSummary;
use crate::utils::extract_manifest;
use clap::Parser;
use clap::ValueEnum;
use smali::android::zip::ApkFile;
use std::path::PathBuf;
use tracing::error;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Parser, ValueEnum)]
/// Output format for the manifest.
pub enum Format {
    /// Pretty-printed JSON.
    Json,
    /// Human-readable text report.
    Printed,
    /// YAML.
    Yaml,
    /// Raw XML.
    Xml,
}

/// Extract the `AndroidManifest.xml` from an APK and print it in the
/// requested `format`.
pub fn handle_manifest(apk_path: PathBuf, format: Format) -> Result<(), String> {
    let apk = ApkFile::from_file(apk_path).map_err(|e| {
        error!("Unable to open APK file due to reason: {e}");
        format!("Unable to open APK file due to reason: {e}")
    })?;

    let manifest = extract_manifest(&apk).map_err(|e| {
        error!("Unable to extract app manifest due to reason: {e}");
        format!("Unable to extract app manifest due to reason: {e}")
    })?;

    match format {
        Format::Xml => {
            let xml = manifest
                .to_string()
                .map_err(|_| "failed to read manifest".to_string())?;
            println!("{}", xml);
        }
        Format::Json => {
            let summary = ManifestSummary::from(&manifest);
            let json = summary
                .to_json()
                .map_err(|_| "failed to read manifest".to_string())?;
            println!("{}", json);
        }
        Format::Yaml => {
            let summary = ManifestSummary::from(&manifest);
            let yaml = summary
                .to_yaml()
                .map_err(|_| "failed to read manifest".to_string())?;
            println!("{}", yaml);
        }
        Format::Printed => {
            let summary = ManifestSummary::from(&manifest);
            print!("{}", summary.to_printed());
        }
    }
    Ok(())
}
