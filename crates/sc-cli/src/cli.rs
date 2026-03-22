use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// $crypt — Next-generation cryptographic analysis framework
#[derive(Parser)]
#[command(
    name = "scrypt",
    version,
    about = "Cryptographic analysis framework for security researchers",
    long_about = "$crypt is a modular framework for protocol analysis, TLS inspection,\nand distributed PCAP processing. Built in Rust with zero-copy semantics."
)]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/default.toml")]
    pub config: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    pub log_level: String,

    /// Output format for structured logs (text, json)
    #[arg(long, default_value = "text")]
    pub log_format: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a PCAP file, dissecting all packets
    Analyze {
        /// Input PCAP/PCAPNG file
        #[arg(short, long)]
        input: PathBuf,

        /// Display filter expression
        #[arg(short, long)]
        filter: Option<String>,

        /// Output format: table, json, jsonl, csv, tree
        #[arg(short = 'F', long, default_value = "table")]
        format: String,

        /// Maximum number of packets to display
        #[arg(short = 'n', long)]
        max_packets: Option<usize>,
    },

    /// Open interactive TUI for packet analysis
    Tui {
        /// Input PCAP/PCAPNG file
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Replay a PCAP file with timing reconstruction
    Replay {
        /// Input PCAP/PCAPNG file
        #[arg(short, long)]
        input: PathBuf,

        /// Speed multiplier (1.0 = real-time, 0 = max speed)
        #[arg(short, long, default_value = "1.0")]
        speed: f64,
    },

    /// Manage plugins
    Plugins {
        #[command(subcommand)]
        action: PluginAction,
    },

    /// Manage mesh network for distributed analysis
    Mesh {
        #[command(subcommand)]
        action: MeshAction,
    },

    /// Show system information and capabilities
    Info,
}

#[derive(Subcommand)]
pub enum PluginAction {
    /// List all loaded plugins
    List,
    /// Reload Lua scripts
    Reload,
}

#[derive(Subcommand)]
pub enum MeshAction {
    /// Start a mesh node
    Start {
        /// Listen port
        #[arg(short, long, default_value = "50051")]
        port: u16,
    },
    /// Analyze a PCAP file using distributed mesh
    Analyze {
        /// Input PCAP file
        #[arg(short, long)]
        input: PathBuf,
        /// Peer addresses (comma-separated)
        #[arg(short, long)]
        peers: String,
    },
}
