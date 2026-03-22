mod cli;
mod output;

use clap::Parser;
use cli::{Cli, Commands, MeshAction, PluginAction};
use sc_core::Config;
use sc_pcap::{PcapAnalyzer, PcapReader};
use sc_plugin::PluginManager;
use sc_protocol::{builtins, new_shared_registry};
use std::path::Path;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    sc_core::logging::init_logging(&cli.log_level, &cli.log_format);

    // Load configuration
    let config = Config::load_or_default(&cli.config);

    info!(version = env!("CARGO_PKG_VERSION"), "$crypt starting");

    match cli.command {
        Commands::Analyze { input, filter, format, max_packets } => {
            cmd_analyze(&config, &input, filter.as_deref(), &format, max_packets)?;
        }
        Commands::Tui { input } => {
            cmd_tui(&config, &input)?;
        }
        Commands::Replay { input, speed } => {
            cmd_replay(&config, &input, speed).await?;
        }
        Commands::Plugins { action } => {
            cmd_plugins(&config, action)?;
        }
        Commands::Mesh { action } => {
            cmd_mesh(&config, action).await?;
        }
        Commands::Info => {
            cmd_info(&config);
        }
    }

    Ok(())
}

fn setup_registry(config: &Config) -> sc_protocol::SharedRegistry {
    let registry = new_shared_registry();

    // Register built-in dissectors
    {
        let mut reg = registry.write().expect("registry lock");
        builtins::register_all(&mut reg);

        // Load and register plugins
        let mut plugin_mgr = PluginManager::new(
            config.plugins.native_dirs.clone(),
            config.plugins.script_dirs.clone(),
        );
        if let Err(e) = plugin_mgr.load_all() {
            tracing::warn!(error = %e, "Failed to load some plugins");
        }
        plugin_mgr.register_dissectors(&mut reg);
    }

    // Register TLS dissector
    {
        let mut reg = registry.write().expect("registry lock");
        reg.register_for_protocol(
            sc_core::Protocol::Tls,
            std::sync::Arc::new(sc_tls::TlsDissector),
        );
    }

    registry
}

fn cmd_analyze(
    config: &Config,
    input: &Path,
    _filter: Option<&str>,
    format: &str,
    max_packets: Option<usize>,
) -> anyhow::Result<()> {
    let reader = PcapReader::open(input)?;
    println!("Loaded {} packets from {}", reader.len(), input.display());

    let registry = setup_registry(config);
    let analyzer = PcapAnalyzer::new(registry, config.general.max_dissection_depth);
    let analyzed = analyzer.analyze_all(reader.packets());

    // Sort by index to restore order after parallel analysis
    let mut analyzed = analyzed;
    analyzed.sort_by_key(|p| p.index);

    let output = match format {
        "json" => output::format_json(&analyzed, max_packets),
        "jsonl" => output::format_jsonl(&analyzed, max_packets),
        "csv" => output::format_csv(&analyzed, max_packets),
        "tree" => output::format_tree(&analyzed, max_packets),
        _ => output::format_table(&analyzed, max_packets),
    };

    println!("{output}");
    Ok(())
}

fn cmd_tui(config: &Config, input: &Path) -> anyhow::Result<()> {
    let reader = PcapReader::open(input)?;
    let registry = setup_registry(config);
    let analyzer = PcapAnalyzer::new(registry, config.general.max_dissection_depth);
    let mut analyzed = analyzer.analyze_all(reader.packets());
    analyzed.sort_by_key(|p| p.index);

    let app = sc_tui::App::new(analyzed);
    app.run()?;
    Ok(())
}

async fn cmd_replay(config: &Config, input: &Path, speed: f64) -> anyhow::Result<()> {
    let reader = PcapReader::open(input)?;
    println!("Replaying {} packets at {}x speed", reader.len(), speed);

    let registry = setup_registry(config);
    let analyzer = PcapAnalyzer::new(registry, config.general.max_dissection_depth);

    let engine = sc_pcap::ReplayEngine::new(speed);
    let mut rx = engine.replay(reader.packets().to_vec(), 1024).await;

    let mut count = 0;
    while let Some(packet) = rx.recv().await {
        let result = analyzer.analyze_one(count, &packet);
        let tree = &result.tree;
        println!(
            "[{:>6}] {} | {} | {} bytes",
            count + 1,
            packet.timestamp,
            tree.top_protocol,
            packet.data.len()
        );
        count += 1;
    }

    println!("\nReplay complete: {} packets", count);
    Ok(())
}

fn cmd_plugins(config: &Config, action: PluginAction) -> anyhow::Result<()> {
    match action {
        PluginAction::List => {
            let mut mgr = PluginManager::new(
                config.plugins.native_dirs.clone(),
                config.plugins.script_dirs.clone(),
            );
            mgr.load_all()?;
            println!("Loaded plugins:");
            for line in mgr.list_plugins() {
                println!("  {line}");
            }
        }
        PluginAction::Reload => {
            println!("Reloading plugins...");
            let mut mgr = PluginManager::new(
                config.plugins.native_dirs.clone(),
                config.plugins.script_dirs.clone(),
            );
            mgr.load_all()?;
            println!("Plugins reloaded successfully");
        }
    }
    Ok(())
}

async fn cmd_mesh(config: &Config, action: MeshAction) -> anyhow::Result<()> {
    match action {
        MeshAction::Start { port } => {
            let addr = format!("[::1]:{port}");
            let node = sc_mesh::MeshNode::new(addr, config.mesh.peers.clone());
            println!("Starting mesh node {} on port {port}", node.node_id());
            node.start().await?;
        }
        MeshAction::Analyze { input, peers } => {
            let peer_list: Vec<String> = peers.split(',').map(String::from).collect();
            println!(
                "Distributed analysis of {} across {} peers",
                input.display(),
                peer_list.len()
            );
            // Placeholder for distributed analysis
            println!("Distributed analysis not yet fully implemented");
        }
    }
    Ok(())
}

fn cmd_info(config: &Config) {
    println!("--------------------------------------------");
    println!("       $crypt Framework v{}", env!("CARGO_PKG_VERSION"));
    println!("--------------------------------------------");

    // Hardware acceleration
    let hw = sc_crypto::detect_hw_acceleration();
    println!("Hardware Acceleration:");
    if hw.is_empty() {
        println!("  None detected");
    } else {
        for feat in &hw {
            println!("  ✓ {feat}");

        }
    }

    // Sandbox capabilities
    println!("Sandbox:");
    for cap in sc_sandbox::capabilities_report() {
        println!("  {cap}");
    }

    // Config
    println!("Configuration:");
    println!("  Max depth: {}", config.general.max_dissection_depth);
    println!("  Log level: {}", config.general.log_level);

    println!("--------------------------------------------");
}
