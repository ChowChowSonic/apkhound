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
pub fn handle_manifest(apk_path: PathBuf, format: Format) -> Result<(), ()> {
    let apk_res = ApkFile::from_file(apk_path);
    if let Ok(apk) = apk_res {
        let manifest_res = extract_manifest(&apk);
        if let Ok(manifest) = manifest_res {
            match format {
                Format::Xml => {
                    let xml = manifest.to_string().map_err(|_| ())?;
                    println!("{}", xml);
                }
                Format::Json => {
                    let summary = ManifestSummary::from(&manifest);
                    let json = summary.to_json().map_err(|_| ())?;
                    println!("{}", json);
                }
                Format::Yaml => {
                    let summary = ManifestSummary::from(&manifest);
                    let yaml = summary.to_yaml().map_err(|_| ())?;
                    println!("{}", yaml);
                }
                Format::Printed => {
                    let summary = ManifestSummary::from(&manifest);
                    print!("{}", summary.to_printed());
                }
            }
            Ok(())
        } else if let Err(e) = manifest_res {
            error!("Unable to extract app manifest due to reason: {e}");
            Err(())
        } else {
            Ok(())
        }
    } else if let Err(app) = apk_res {
        error!("Unable to open APK file due to reason: {app}");
        Err(())
    } else {
        Ok(())
    }
}
