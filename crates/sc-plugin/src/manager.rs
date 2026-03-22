use crate::lua_engine::LuaEngine;
use crate::traits::{Plugin, PluginContext, PluginMetadata};
use sc_core::{Result, ShadowError};
use std::path::PathBuf;
use tracing::info;

/// Central plugin manager that discovers, loads, and manages all plugins.
pub struct PluginManager {
    lua_engine: LuaEngine,
    native_dirs: Vec<PathBuf>,
    script_dirs: Vec<PathBuf>,
}

impl PluginManager {
    pub fn new(native_dirs: Vec<PathBuf>, script_dirs: Vec<PathBuf>) -> Self {
        Self {
            lua_engine: LuaEngine::new(),
            native_dirs,
            script_dirs,
        }
    }

    /// Discover and load all plugins from configured directories.
    pub fn load_all(&mut self) -> Result<()> {
        // Load Lua scripts
        for dir in &self.script_dirs.clone() {
            self.lua_engine.load_directory(dir)?;
        }

        info!(
            lua_count = self.lua_engine.count(),
            "Plugin loading complete"
        );

        Ok(())
    }

    /// Register all loaded plugin dissectors into the protocol registry.
    pub fn register_dissectors(&self, registry: &mut sc_protocol::DissectorRegistry) {
        self.lua_engine.register_all(registry);
    }

    /// Get a list of all loaded plugin metadata.
    pub fn list_plugins(&self) -> Vec<String> {
        let mut list = Vec::new();
        list.push(format!("Lua plugins: {}", self.lua_engine.count()));
        list
    }
}
