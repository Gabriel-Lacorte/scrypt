use sc_core::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Type of functionality a plugin provides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginType {
    Dissector,
    Analyzer,
    Transform,
}

/// Metadata describing a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub plugin_type: PluginType,
}

impl fmt::Display for PluginMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{} by {} [{}]",
            self.name, self.version, self.author,
            match self.plugin_type {
                PluginType::Dissector => "dissector",
                PluginType::Analyzer => "analyzer",
                PluginType::Transform => "transform",
            })
    }
}

/// Context provided to plugins during initialization.
pub struct PluginContext {
    pub config: sc_core::Config,
    pub registry: sc_protocol::SharedRegistry,
}

/// The core trait that all plugins must implement.
pub trait Plugin: Send + Sync {
    /// Return metadata about this plugin.
    fn metadata(&self) -> PluginMetadata;

    /// Initialize the plugin with the given context.
    fn init(&mut self, ctx: &PluginContext) -> Result<()>;

    /// Shut down the plugin, releasing resources.
    fn shutdown(&self) -> Result<()>;
}
