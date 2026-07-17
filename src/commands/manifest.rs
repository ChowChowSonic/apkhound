use crate::manifest_summary::ManifestSummary;
use crate::utils::extract_manifest;
use clap::Parser;
use clap::ValueEnum;
use smali::android::zip::ApkFile;
use std::path::PathBuf;
use tracing::error;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Parser, ValueEnum)]
pub enum Format {
    Json,
    Printed,
    Yaml,
    Xml,
}

pub fn handle_manifest(apk_path: PathBuf, format: Format) {
    let apk_res = ApkFile::from_file(apk_path);
    if let Ok(apk) = apk_res {
        let manifest_res = extract_manifest(&apk);
        if let Ok(manifest) = manifest_res {
            match format {
                Format::Xml => {
                    if let Ok(xml) = manifest.to_string() {
                        println!("{}", xml);
                    }
                }
                Format::Json => {
                    let summary = ManifestSummary::from(&manifest);
                    if let Ok(json) = summary.to_json() {
                        println!("{}", json);
                    }
                }
                Format::Yaml => {
                    let summary = ManifestSummary::from(&manifest);
                    if let Ok(yaml) = summary.to_yaml() {
                        println!("{}", yaml);
                    }
                }
                Format::Printed => {
                    let summary = ManifestSummary::from(&manifest);
                    print!("{}", summary.to_printed());
                }
            }
        } else if let Err(e) = manifest_res {
            error!("Unable to extract app manifest due to reason: {e}");
        }
    } else if let Err(app) = apk_res {
        error!("Unable to open APK file due to reason: {app}");
    }
}
