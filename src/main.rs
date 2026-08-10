use apkhound::commands::{self, manifest::Format};
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
    /// Trace call paths between methods matching two regexes
    Trace {
        /// Regex matching source method signatures (class:method)
        src_regex: String,
        /// Regex matching destination method signatures (class:method)
        dest_regex: String,
        /// File whose non-empty lines are source regexes (overrides src_regex)
        #[arg(short = 'S', long = "src-from-file")]
        src_from_file: Option<PathBuf>,
        /// File whose non-empty lines are destination regexes (overrides dest_regex)
        #[arg(short = 'D', long = "dest-from-file")]
        dest_from_file: Option<PathBuf>,
        #[arg(value_enum, short = 'f', long = "format", default_value_t = commands::manifest::Format::Printed)]
        format: Format,
        /// Paths to the APK files
        apks: Vec<PathBuf>,
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
        #[arg(short = 'c', long = "change-threshold", default_value_t = 0.0)]
        change_threshold: f64,
        /// Number of Weisfeiler-Lehman refinement iterations
        #[arg(short = 'i', long = "wl-iterations", default_value_t = 3)]
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
        /// Enable node-label consistency check for more precise matching
        #[arg(short = 'm', long = "node-matching", default_value_t = false)]
        node_matching: bool,
        /// Weight of API-call fingerprint in combined score (0.0 = pure WL, 1.0 = pure API)
        #[arg(long = "api-weight", default_value_t = 0.2)]
        api_weight: f64,
        /// Weight of hierarchical ancestor-consistency bonus (0.0 = disabled)
        #[arg(long = "hier-weight", default_value_t = 0.7)]
        hier_weight: f64,
        /// Weight of string-constant fingerprint in combined score (0.0 = disabled)
        #[arg(long = "string-weight", default_value_t = 0.3)]
        string_weight: f64,
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
    let result = match args {
        Commands::Callgraph { apk_path, filters } => {
            commands::callgraph::handle_callgraph(apk_path, filters)
        }
        Commands::Compare {
            old_apk,
            new_apk,
            filters,
        } => commands::compare::handle_compare(old_apk, new_apk, filters),
        Commands::Extract {
            old_apk,
            new_apk,
            output_dir,
            class_filters,
            smali_filters,
        } => commands::extract::handle_extract(
            old_apk,
            new_apk,
            output_dir,
            class_filters,
            smali_filters,
        ),
        Commands::Trace {
            src_regex,
            dest_regex,
            src_from_file,
            dest_from_file,
            format,
            apks,
        } => commands::trace::handle_trace(
            src_regex,
            dest_regex,
            src_from_file,
            dest_from_file,
            format,
            apks,
        ),
        Commands::Match {
            old_apk,
            new_apk,
            threshold,
            change_threshold,
            wl_iterations,
            csv,
            show_details,
            filters,
            node_matching,
            api_weight,
            hier_weight,
            string_weight,
        } => commands::match_cmd::handle_match(
            old_apk,
            new_apk,
            commands::match_cmd::MatchConfig {
                threshold,
                change_threshold,
                wl_iterations,
                csv,
                show_details,
                filters,
                use_node_matching: node_matching,
                api_weight,
                hier_weight,
                string_weight,
            },
        ),
        Commands::Permissions { old_apk, new_apk } => {
            commands::permissions::handle_permissions(old_apk, new_apk)
        }
        Commands::Manifest { apk_path, format } => {
            commands::manifest::handle_manifest(apk_path, format)
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
