use crate::traits::{PluginMetadata, PluginType};
use mlua::prelude::*;
use sc_core::{Result, ShadowError};
use sc_protocol::*;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// A Lua-based protocol dissector wrapped in Rust Dissector trait.
struct LuaDissector {
    lua: Mutex<Lua>,
    script_path: String,
    meta: PluginMetadata,
}

impl LuaDissector {
    fn new(path: &Path) -> Result<Self> {
        let lua = Lua::new();

        // Sandbox: remove dangerous modules
        {
            let globals = lua.globals();
            let _ = globals.set("os", mlua::Value::Nil);
            let _ = globals.set("io", mlua::Value::Nil);
            let _ = globals.set("debug", mlua::Value::Nil);
            let _ = globals.set("loadfile", mlua::Value::Nil);
            let _ = globals.set("dofile", mlua::Value::Nil);
        }

        // Register the `sc` helper table
        let sc_table = lua.create_table().map_err(|e| ShadowError::Plugin {
            message: format!("failed to create sc table: {e}"),
        })?;

        // sc.field(name, display_value, offset, length) -> table
        let field_fn = lua.create_function(|lua_ctx, (name, display_value, offset, length): (String, String, usize, usize)| {
            let t = lua_ctx.create_table()?;
            t.set("name", name)?;
            t.set("value", display_value)?;
            t.set("offset", offset)?;
            t.set("len", length)?;
            Ok(mlua::Value::Table(t))
        }).map_err(|e| ShadowError::Plugin {
            message: format!("failed to create field function: {e}"),
        })?;
        sc_table.set("field", field_fn).map_err(|e| ShadowError::Plugin {
            message: format!("failed to set field function: {e}"),
        })?;

        // sc.log(level, msg)
        let log_fn = lua.create_function(|_, (level, msg): (String, String)| {
            match level.as_str() {
                "debug" => tracing::debug!(plugin = "lua", "{}", msg),
                "info" => tracing::info!(plugin = "lua", "{}", msg),
                "warn" => tracing::warn!(plugin = "lua", "{}", msg),
                "error" => tracing::error!(plugin = "lua", "{}", msg),
                _ => tracing::info!(plugin = "lua", "{}", msg),
            }
            Ok(())
        }).map_err(|e| ShadowError::Plugin {
            message: format!("failed to create log function: {e}"),
        })?;
        sc_table.set("log", log_fn).map_err(|e| ShadowError::Plugin {
            message: format!("failed to set log function: {e}"),
        })?;

        lua.globals().set("sc", sc_table).map_err(|e| ShadowError::Plugin {
            message: format!("failed to set sc global: {e}"),
        })?;

        // Load and execute the script
        let source = std::fs::read_to_string(path).map_err(|e| ShadowError::Plugin {
            message: format!("failed to read Lua script {}: {e}", path.display()),
        })?;

        lua.load(&source).exec().map_err(|e| ShadowError::Plugin {
            message: format!("Lua script error in {}: {e}", path.display()),
        })?;

        // Extract metadata from the script's `plugin` table
        let meta = Self::extract_metadata(&lua, path)?;

        Ok(Self {
            lua: Mutex::new(lua),
            script_path: path.display().to_string(),
            meta,
        })
    }

    fn extract_metadata(lua: &Lua, path: &Path) -> Result<PluginMetadata> {
        let globals = lua.globals();
        let plugin_table: LuaTable = globals.get("plugin").map_err(|_| ShadowError::Plugin {
            message: format!("Lua script {} missing 'plugin' table", path.display()),
        })?;

        let name: String = plugin_table.get("name").unwrap_or_else(|_| {
            path.file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into())
        });
        let version: String = plugin_table.get("version").unwrap_or_else(|_| "0.1.0".into());
        let author: String = plugin_table.get("author").unwrap_or_else(|_| "unknown".into());
        let description: String = plugin_table.get("description").unwrap_or_else(|_| String::new());

        Ok(PluginMetadata {
            name,
            version,
            author,
            description,
            plugin_type: PluginType::Dissector,
        })
    }
}

impl Dissector for LuaDissector {
    fn id(&self) -> DissectorId {
        DissectorId(format!("lua:{}", self.meta.name))
    }

    fn name(&self) -> &str {
        &self.meta.name
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        let lua = self.lua.lock().unwrap();
        let globals = lua.globals();
        let func: LuaFunction = match globals.get("can_dissect") {
            Ok(f) => f,
            Err(_) => return Confidence::None,
        };

        // Pass data length and port hints to Lua
        let result: std::result::Result<String, _> = func.call((
            data.len(),
            context.src_port.unwrap_or(0),
            context.dst_port.unwrap_or(0),
        ));

        match result {
            Ok(level) => match level.as_str() {
                "exact" => Confidence::Exact,
                "high" => Confidence::High,
                "medium" => Confidence::Medium,
                "low" => Confidence::Low,
                _ => Confidence::None,
            },
            Err(e) => {
                warn!(script = %self.script_path, error = %e, "Lua can_dissect failed");
                Confidence::None
            }
        }
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        context: &mut DissectionContext,
    ) -> Result<DissectedLayer<'a>> {
        let lua = self.lua.lock().unwrap();
        let globals = lua.globals();
        let func: LuaFunction = globals.get("dissect").map_err(|e| ShadowError::Plugin {
            message: format!("Lua script {} missing 'dissect' function: {e}", self.script_path),
        })?;

        // Convert data to a Lua string (byte sequence)
        let lua_data = lua.create_string(data).map_err(|e| ShadowError::Plugin {
            message: format!("failed to pass data to Lua: {e}"),
        })?;

        let result: LuaTable = func.call((lua_data, context.src_port.unwrap_or(0), context.dst_port.unwrap_or(0)))
            .map_err(|e| ShadowError::Plugin {
                message: format!("Lua dissect failed in {}: {e}", self.script_path),
            })?;

        // Extract protocol name and summary from result table
        let protocol: String = result.get("protocol").unwrap_or_else(|_| "Unknown".into());
        let summary: String = result.get("summary").unwrap_or_else(|_| String::new());
        let header_len: usize = result.get("header_len").unwrap_or(0);

        // Extract fields
        let mut fields = Vec::new();
        if let Ok(fields_table) = result.get::<LuaTable>("fields") {
            for pair in fields_table.pairs::<usize, LuaTable>() {
                if let Ok((_, field_table)) = pair {
                    let name: String = field_table.get("name").unwrap_or_default();
                    let value: String = field_table.get("value").unwrap_or_default();
                    let offset: usize = field_table.get("offset").unwrap_or(0);
                    let len: usize = field_table.get("len").unwrap_or(0);
                    fields.push(Field {
                        name,
                        display_value: value,
                        byte_range: offset..offset + len,
                        field_type: FieldType::String,
                    });
                }
            }
        }

        let node = ProtocolNode {
            protocol,
            byte_range: 0..header_len,
            fields,
            summary,
        };

        let remaining = if header_len < data.len() {
            &data[header_len..]
        } else {
            &[]
        };

        // Extract next protocol hint
        let next_hint: Option<String> = result.get("next_protocol").ok();
        let next_protocol = next_hint.and_then(|h| match h.as_str() {
            "tcp" => Some(sc_core::Protocol::Tcp),
            "udp" => Some(sc_core::Protocol::Udp),
            "tls" => Some(sc_core::Protocol::Tls),
            "http" => Some(sc_core::Protocol::Http),
            "dns" => Some(sc_core::Protocol::Dns),
            _ => None,
        });

        Ok(DissectedLayer {
            node,
            remaining,
            next_protocol,
        })
    }
}

/// Lua plugin engine that loads and manages Lua scripts.
pub struct LuaEngine {
    dissectors: Vec<Arc<LuaDissector>>,
}

impl LuaEngine {
    pub fn new() -> Self {
        Self {
            dissectors: Vec::new(),
        }
    }

    /// Load all Lua scripts from a directory.
    pub fn load_directory(&mut self, dir: &Path) -> Result<()> {
        if !dir.exists() {
            debug!(path = %dir.display(), "Lua script directory does not exist, skipping");
            return Ok(());
        }

        for entry in std::fs::read_dir(dir).map_err(|e| ShadowError::Plugin {
            message: format!("failed to read plugin dir {}: {e}", dir.display()),
        })? {
            let entry = entry.map_err(|e| ShadowError::Plugin {
                message: format!("failed to read dir entry: {e}"),
            })?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "lua") {
                info!(script = %path.display(), "Loading Lua plugin");
                match LuaDissector::new(&path) {
                    Ok(dissector) => {
                        info!(name = %dissector.meta.name, "Loaded Lua dissector");
                        self.dissectors.push(Arc::new(dissector));
                    }
                    Err(e) => {
                        warn!(script = %path.display(), error = %e, "Failed to load Lua plugin");
                    }
                }
            }
        }

        Ok(())
    }

    /// Register all loaded Lua dissectors into a protocol registry.
    pub fn register_all(&self, registry: &mut sc_protocol::DissectorRegistry) {
        for dissector in &self.dissectors {
            // Register as a generic dissector (will match based on can_dissect)
            registry.register_for_port(0, Arc::clone(dissector) as Arc<dyn Dissector>);
        }
    }

    /// Get loaded dissector count.
    pub fn count(&self) -> usize {
        self.dissectors.len()
    }
}

impl Default for LuaEngine {
    fn default() -> Self {
        Self::new()
    }
}
