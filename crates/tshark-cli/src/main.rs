mod commands;
mod output;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tshark", about = "Network protocol analyzer", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture packets from a network interface
    Capture {
        /// Network interface name
        #[arg(short, long)]
        interface: String,
        /// BPF capture filter
        #[arg(short = 'f', long)]
        capture_filter: Option<String>,
        /// Display filter expression
        #[arg(short = 'Y', long)]
        display_filter: Option<String>,
        /// Stop after N packets
        #[arg(short = 'c', long)]
        count: Option<usize>,
        /// Verbose output (show all fields)
        #[arg(short = 'V', long)]
        verbose: bool,
        /// Show hex dump
        #[arg(short = 'x', long)]
        hex_dump: bool,
        /// Output format: text, json
        #[arg(short = 'T', long, value_parser = ["text", "json"])]
        format: Option<String>,
    },
    /// Read packets from a capture file
    Read {
        /// Path to pcap file
        file: PathBuf,
        /// Display filter expression
        #[arg(short = 'Y', long)]
        display_filter: Option<String>,
        /// Verbose output (show all fields)
        #[arg(short = 'V', long)]
        verbose: bool,
        /// Show hex dump
        #[arg(short = 'x', long)]
        hex_dump: bool,
        /// Output format: text, json
        #[arg(short = 'T', long, value_parser = ["text", "json"])]
        format: Option<String>,
    },
    /// List available network interfaces
    Interfaces,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture {
            interface,
            capture_filter,
            display_filter,
            count,
            verbose,
            hex_dump,
            format,
        } => commands::capture::run(
            &interface,
            capture_filter.as_deref(),
            display_filter.as_deref(),
            count,
            verbose,
            hex_dump,
            format.as_deref(),
        ),
        Commands::Read {
            file,
            display_filter,
            verbose,
            hex_dump,
            format,
        } => commands::read::run(
            &file,
            display_filter.as_deref(),
            verbose,
            hex_dump,
            format.as_deref(),
        ),
        Commands::Interfaces => commands::interfaces::run(),
    }
}
