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
        /// Run matching analysis between APKs first and use matched classes as source of truth
        #[arg(long = "match-obfuscated")]
        match_obfuscated: bool,
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
        /// Run matching analysis between APKs first and use matched classes as source of truth
        #[arg(long = "match-obfuscated")]
        match_obfuscated: bool,
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
        /// Run matching analysis between APKs first and use matched classes as source of truth
        #[arg(long = "match-obfuscated")]
        match_obfuscated: bool,
    },
    /// Trace call paths between methods matching two regexes
    Trace {
        /// Regex matching source method signatures (class:method)
        src_regex: String,
        /// Regex matching destination method signatures (class:method)
        dest_regex: String,
        /// Treat <SRC_REGEX> as a path to a file whose non-empty lines are source regexes
        #[arg(short = 'S', long = "src-from-file")]
        src_from_file: bool,
        /// Treat <DEST_REGEX> as a path to a file whose non-empty lines are destination regexes
        #[arg(short = 'D', long = "dest-from-file")]
        dest_from_file: bool,
        #[arg(value_enum, short = 'f', long = "format", default_value_t = commands::manifest::Format::Printed)]
        format: Format,
        /// Paths to the APK files
        apks: Vec<PathBuf>,
        /// Run matching analysis between APKs first and use matched classes as source of truth
        #[arg(long = "match-obfuscated")]
        match_obfuscated: bool,
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
        /// Run matching analysis between APKs first and use matched classes as source of truth
        #[arg(long = "match-obfuscated")]
        match_obfuscated: bool,
        /// Output application change summary metrics (outputs only the summary unless a format like --csv is specified)
        #[arg(long = "summary")]
        summary: bool,
        /// Output only the overall change scalar (float in [0.0, 1.0]), ideal for scripting
        #[arg(long = "score-only")]
        score_only: bool,
        /// Exclude scoring features from the combined score: coarse components (wl, api, string, hier),
        /// WL feature dimensions (in_degree, num_params, has_branches, ...), or API categories
        /// (api_android, api_androidx, api_java, api_kotlin, api_other). Repeatable or comma-separated.
        #[arg(long = "exclude-feature", value_delimiter = ',')]
        exclude_features: Vec<apkhound::matching::Feature>,
    },
    /// Compare manifest permissions between two APKs, or list permissions of one
    Permissions {
        old_apk: PathBuf,
        new_apk: Option<PathBuf>,
        /// Run matching analysis between APKs first and use matched classes as source of truth
        #[arg(long = "match-obfuscated")]
        match_obfuscated: bool,
    },
    /// Extract and display AndroidManifest in a choice of formats
    Manifest {
        apk_path: PathBuf,
        #[arg(value_enum, default_value_t = commands::manifest::Format::Printed)]
        format: commands::manifest::Format,
        /// Run matching analysis between APKs first and use matched classes as source of truth
        #[arg(long = "match-obfuscated")]
        match_obfuscated: bool,
    },
    /// Compute statistics for one or two APK files (diffs them when both given)
    Stats {
        /// Path to an APK file (exactly one or two)
        #[arg(required = true, num_args = 1..=2)]
        apks: Vec<PathBuf>,
        /// Regex filter for class names (can be specified multiple times)
        #[arg(short = 'f', long = "filterclass")]
        filters: Vec<String>,
        /// Include call-graph metrics (requires an extra parse pass)
        #[arg(short = 'g', long = "graph")]
        graph: bool,
        /// Output format
        #[arg(value_enum, long = "format", default_value_t = commands::stats::StatsFormat::Printed)]
        format: commands::stats::StatsFormat,
        /// Run matching analysis between APKs first and use matched classes as source of truth
        #[arg(long = "match-obfuscated")]
        match_obfuscated: bool,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = Commands::parse();
    let result = match args {
        Commands::Callgraph {
            apk_path,
            filters,
            match_obfuscated,
        } => commands::callgraph::handle_callgraph(apk_path, filters, match_obfuscated),
        Commands::Compare {
            old_apk,
            new_apk,
            filters,
            match_obfuscated,
        } => commands::compare::handle_compare(old_apk, new_apk, filters, match_obfuscated),
        Commands::Extract {
            old_apk,
            new_apk,
            output_dir,
            class_filters,
            smali_filters,
            match_obfuscated,
        } => commands::extract::handle_extract(
            old_apk,
            new_apk,
            output_dir,
            class_filters,
            smali_filters,
            match_obfuscated,
        ),
        Commands::Trace {
            src_regex,
            dest_regex,
            src_from_file,
            dest_from_file,
            format,
            apks,
            match_obfuscated,
        } => commands::trace::handle_trace(
            src_regex,
            dest_regex,
            src_from_file,
            dest_from_file,
            format,
            apks,
            match_obfuscated,
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
            match_obfuscated,
            summary,
            score_only,
            exclude_features,
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
                match_obfuscated,
                summary,
                score_only,
                exclude_features,
            },
        ),
        Commands::Permissions {
            old_apk,
            new_apk,
            match_obfuscated,
        } => commands::permissions::handle_permissions(old_apk, new_apk, match_obfuscated),
        Commands::Manifest {
            apk_path,
            format,
            match_obfuscated,
        } => commands::manifest::handle_manifest(apk_path, format, match_obfuscated),
        Commands::Stats {
            apks,
            filters,
            graph,
            format,
            match_obfuscated,
        } => commands::stats::handle_stats(apks, filters, graph, format, match_obfuscated),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
