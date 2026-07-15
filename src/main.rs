mod callgraph;
mod compare;
use crate::callgraph::iterate_over_dex_files;
use crate::compare::{
    EditType, dump_changes_between_classes, find_changes_between_classes, unpack_apk_classes,
};
use clap::Parser;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use smali::android::zip::ApkFile;
use smali::types::{SmaliClass, SmaliMethod};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::error;
use tracing::trace;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
enum Commands {
    Callgraph {
        apk_path: PathBuf,
        outfile: Option<PathBuf>,
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
    },
    Compare {
        old_apk: PathBuf,
        new_apk: PathBuf,
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
    },
    Extract {
        old_apk: PathBuf,
        new_apk: PathBuf,
        output_dir: PathBuf,
        #[arg(short = 'f', long = "filterclass")]
        class_filters: Vec<String>,
        #[arg(short = 's', long = "filtersmali")]
        smali_filters: Vec<String>,
    },
}

fn build_regex(filters: &[String]) -> Vec<Regex> {
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

fn main() {
    tracing_subscriber::fmt()
        //    .with_max_level(LevelFilter::INFO)
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

            let regex: Vec<Regex> = build_regex(&filters);
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
        Commands::Compare {
            old_apk,
            new_apk,
            filters,
        } => {
            let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
                .par_iter()
                .map(ApkFile::from_file)
                .collect();
            if let Ok(new) = &apks[1]
                && let Ok(old) = &apks[0]
            {
                let regex: Vec<Regex> = build_regex(&filters);
                let old_classes = unpack_apk_classes(old, &regex)
                    .par_iter()
                    .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    })
                    .reduce(HashMap::new, |mut accum, mut res| {
                        accum.extend(res.drain());
                        accum
                    });
                let new_classes = unpack_apk_classes(new, &regex)
                    .par_iter()
                    .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    })
                    .reduce(HashMap::new, |mut accum, mut res| {
                        accum.extend(res.drain());
                        accum
                    });
                let res = find_changes_between_classes(new_classes, old_classes);
                for x in res {
                    match x {
                        EditType::Change(x) => println!("CHANGED: {x}"),
                        EditType::Addition(x) => println!("ADDED: {x}"),
                        EditType::Remove(x) => println!("REMOVED: {x}"),
                    }
                }
            } else if let Err(old) = &apks[0] {
                error!("Error parsing old apk: {old}");
            } else if let Err(new) = &apks[1] {
                error!("Error parsing new apk: {new}");
            }
        }

        Commands::Extract {
            old_apk,
            new_apk,
            output_dir,
            class_filters,
            smali_filters,
        } => {
            let apks: Vec<Result<ApkFile, _>> = vec![old_apk, new_apk]
                .par_iter()
                .map(ApkFile::from_file)
                .collect();
            if let Ok(new) = &apks[1]
                && let Ok(old) = &apks[0]
            {
                let regex: Vec<Regex> = build_regex(&class_filters);
                let smali_regex: Vec<Regex> = build_regex(&smali_filters);
                let old_classes = unpack_apk_classes(old, &regex)
                    .par_iter()
                    .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    })
                    .reduce(HashMap::new, |mut accum, mut res| {
                        accum.extend(res.drain());
                        accum
                    });
                let new_classes = unpack_apk_classes(new, &regex)
                    .par_iter()
                    .fold(HashMap::<String, SmaliClass>::new, |mut accum, item| {
                        accum.insert(item.name.as_java_type(), item.clone());
                        accum
                    })
                    .reduce(HashMap::new, |mut accum, mut res| {
                        accum.extend(res.drain());
                        accum
                    });
                let _ = dump_changes_between_classes(
                    new_classes,
                    old_classes,
                    &output_dir,
                    &smali_regex,
                );
            } else if let Err(old) = &apks[0] {
                error!("Error parsing old apk: {old}");
            } else if let Err(new) = &apks[1] {
                error!("Error parsing new apk: {new}");
            }
        }
    }
}
