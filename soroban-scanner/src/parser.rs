/// CLI argument parser for the detectors-runner tool.
///
/// Defines `Cli` and `Commands` types for parsing subcommands and options
/// using the `clap` crate.
use clap::{Parser, Subcommand};

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    Scan {
        code: Vec<std::path::PathBuf>,
        #[arg(long = "detectors", required = false, value_parser, num_args = 1..)]
        detectors: Option<Vec<String>>,
        #[arg(long = "project-root", required = false, value_parser)]
        project_root: Option<std::path::PathBuf>,
        #[arg(long = "load", required = false, value_parser)]
        load_lib: Option<std::path::PathBuf>,
        /// Skip any file whose canonical path contains one of the given
        /// substrings. Repeatable. Matches the walker's raw path separators
        /// (`/` on unix, `\\` on windows), so prefer simple fragments like
        /// `vendor/` or `target/`.
        #[arg(long = "exclude", required = false, value_parser, num_args = 1..)]
        exclude: Option<Vec<String>>,
    },
    Metadata,
}

#[derive(Parser, Debug)]
#[command(name = "soroban-scanner", about = "Soroban Scanner")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}
