use apkhound::commands;
use clap::Parser;
use std::path::PathBuf;

//#[global_allocator]
//static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
//static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
enum Commands {
    /// Extract a call graph from an APK
    Callgraph {
        /// Path to the APK file
        apk_path: Vec<PathBuf>,
        /// Regex filter for class names (can be specified multiple times)
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
    },
    /// Compare two APKs and list class-level additions, removals, and changes
    Compare {
        /// Path to the original APK
        old_apk: PathBuf,
        /// Path to the modified APK
        new_apk: PathBuf,
        /// Regex filter for class names (can be specified multiple times)
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
    },
    /// Extract changed method smali to a directory
    Extract {
        /// Path to the original APK
        old_apk: PathBuf,
        /// Path to the modified APK
        new_apk: PathBuf,
        /// Directory to write extracted smali files to
        output_dir: PathBuf,
        /// Regex filter for class names (can be specified multiple times)
        #[arg(short = 'f', long = "filterclass")]
        class_filters: Vec<String>,
        /// Regex filter for method signatures (can be specified multiple times)
        #[arg(short = 's', long = "filtersmali")]
        smali_filters: Vec<String>,
    },
    /// Match packages across two APKs using graph isomorphism
    #[command(name = "match")]
    Match {
        /// Path to the original APK
        old_apk: PathBuf,
        /// Path to the modified APK
        new_apk: PathBuf,
        /// Similarity threshold to consider packages a match
        #[arg(short = 't', long = "threshold", default_value_t = 0.8)]
        threshold: f64,
        /// Minimum similarity to consider two packages related
        #[arg(long = "change-threshold", default_value_t = 0.0)]
        change_threshold: f64,
        /// Number of Weisfeiler-Lehman refinement iterations
        #[arg(long = "wl-iterations", default_value_t = 3)]
        wl_iterations: usize,
        /// Output in CSV format instead of a formatted table
        #[arg(long = "csv")]
        csv: bool,
        /// Show method counts for matched/changed packages
        #[arg(short = 'd', long = "show-details")]
        show_details: bool,
        /// Regex filter for class names (can be specified multiple times)
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
    },
    /// Compare manifest permissions between two APKs, or list permissions of one
    Permissions {
        old_apk: PathBuf,
        new_apk: Option<PathBuf>,
    },
    /// Extract and display AndroidManifest in a choice of formats
    Manifest {
        apk_path: PathBuf,
        #[arg(value_enum, default_value_t = commands::manifest::Format::Printed)]
        format: commands::manifest::Format,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = Commands::parse();
    match args {
        Commands::Callgraph { apk_path, filters } => {
            let _ = commands::callgraph::handle_callgraph(apk_path, filters);
        }
        Commands::Compare {
            old_apk,
            new_apk,
            filters,
        } => {
            let _ = commands::compare::handle_compare(old_apk, new_apk, filters);
        }
        Commands::Extract {
            old_apk,
            new_apk,
            output_dir,
            class_filters,
            smali_filters,
        } => {
            let _ = commands::extract::handle_extract(
                old_apk,
                new_apk,
                output_dir,
                class_filters,
                smali_filters,
            );
        }
        Commands::Match {
            old_apk,
            new_apk,
            threshold,
            change_threshold,
            wl_iterations,
            csv,
            show_details,
            filters,
        } => {
            let _ = commands::match_cmd::handle_match(
                old_apk,
                new_apk,
                commands::match_cmd::MatchConfig {
                    threshold,
                    change_threshold,
                    wl_iterations,
                    csv,
                    show_details,
                    filters,
                },
            );
        }
        Commands::Permissions { old_apk, new_apk } => {
            let _ = commands::permissions::handle_permissions(old_apk, new_apk);
        }
        Commands::Manifest { apk_path, format } => {
            let _ = commands::manifest::handle_manifest(apk_path, format);
        }
    }
}
