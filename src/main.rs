mod callgraph;
use crate::callgraph::iterate_over_dex_files;
use clap::Parser;
use regex::Regex;
use smali::android::zip::ApkFile;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::trace;
use tracing::{error, level_filters::LevelFilter};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
enum Commands {
    Callgraph {
        apk_path: PathBuf,
        outfile: Option<PathBuf>,
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .with_writer(std::io::stderr)
        .init();
    let args = Commands::parse();
    match args {
        Commands::Callgraph {
            apk_path,
            outfile,
            filters,
        } => {
            trace!("File provided: {:?}", &apk_path);
            trace!("OutFile provided: {:?}", &outfile);
            let mut regex: Vec<Regex> = Vec::new();
            for x in filters {
                let regex_val = Regex::from_str(&x);
                if let Ok(r) = regex_val {
                    regex.push(r);
                } else if let Err(e) = regex_val {
                    error!("Failed to parse regex {x:?} due to reason: {e}");
                }
            }
            let apk_result = ApkFile::from_file(&apk_path);
            if let Ok(apk) = apk_result {
                let res = iterate_over_dex_files(&apk, &regex);
                println!("digraph {{");
                res.iter().for_each(|x| {
                    for y in x.1 {
                        println!("\"{}\" -> \"{}\"; ", x.0, y)
                    }
                });
                println!("}}");
            } else if let Err(e) = apk_result {
                error!("Failed to parse APK file: {e}");
            }
        }
    }
}
