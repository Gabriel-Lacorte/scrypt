use crate::lua_engine::LuaEngine;
use crate::native_loader::{self, NativePlugin};
use sc_core::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// Central plugin manager that discovers, loads, and manages all plugins.
pub struct PluginManager {
    lua_engine: LuaEngine,
    native_plugins: Vec<Arc<NativePlugin>>,
    native_dirs: Vec<PathBuf>,
    script_dirs: Vec<PathBuf>,
}

impl PluginManager {
    pub fn new(native_dirs: Vec<PathBuf>, script_dirs: Vec<PathBuf>) -> Self {
        Self {
            lua_engine: LuaEngine::new(),
            native_plugins: Vec::new(),
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

        // Load native plugins from .so/.dylib files
        for dir in &self.native_dirs.clone() {
            let loaded = native_loader::load_native_plugins(dir);
            self.native_plugins.extend(loaded);
        }

        info!(
            lua_count = self.lua_engine.count(),
            native_count = self.native_plugins.len(),
            "Plugin loading complete"
        );

        Ok(())
    }

    /// Register all loaded plugin dissectors into the protocol registry.
    pub fn register_dissectors(&self, registry: &mut sc_protocol::DissectorRegistry) {
        use sc_protocol::Dissector;
        use std::sync::Arc;

        self.lua_engine.register_all(registry);

        for plugin in &self.native_plugins {
            registry.register_for_port(0, Arc::clone(plugin) as Arc<dyn Dissector>);
        }
    }

    /// Get a list of all loaded plugin metadata.
    pub fn list_plugins(&self) -> Vec<String> {
        let mut list = Vec::new();
        list.push(format!("Lua plugins: {}", self.lua_engine.count()));
        list.push(format!("Native plugins: {}", self.native_plugins.len()));
        for p in &self.native_plugins {
            list.push(format!("  - {}", p.metadata()));
        }
        list
    }
}
