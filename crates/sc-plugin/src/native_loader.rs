use crate::traits::{PluginMetadata, PluginType};
use libloading::{Library, Symbol};
use sc_core::{Result, ShadowError};
use sc_protocol::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

/// ABI version for native plugins. Plugins must match this to be loaded.
pub const PLUGIN_ABI_VERSION: u32 = 1;

/// Raw C ABI vtable returned by native plugins via `scrypt_plugin_init`.
///
/// # Safety
///
/// All function pointers must remain valid for the lifetime of the loaded library.
/// The `dissect` callback receives borrowed data that must not be stored beyond the call.
#[repr(C)]
pub struct PluginVTable {
    /// ABI version — must equal `PLUGIN_ABI_VERSION`.
    pub abi_version: u32,
    /// Return plugin metadata as a null-terminated JSON string.
    /// Caller frees nothing — the string must be static or leak-allocated.
    pub metadata: extern "C" fn() -> *const std::ffi::c_char,
    /// Check if this dissector can handle the given data.
    /// Returns a confidence value: 0=None, 1=Low, 2=Medium, 3=High, 4=Exact.
    pub can_dissect: extern "C" fn(data: *const u8, data_len: usize) -> u32,
    /// Dissect the given data buffer.
    /// Writes results into the provided output buffer as JSON.
    /// Returns the number of bytes consumed from the input, or 0 on failure.
    pub dissect: extern "C" fn(
        data: *const u8,
        data_len: usize,
        output_buf: *mut u8,
        output_buf_len: usize,
    ) -> usize,
}

/// Type signature for the plugin init function exported by native dylibs.
type PluginInitFn = unsafe extern "C" fn() -> *const PluginVTable;

/// A loaded native plugin backed by a dynamic library.
pub struct NativePlugin {
    _library: Library,
    vtable: &'static PluginVTable,
    metadata: PluginMetadata,
    #[allow(dead_code)]
    path: PathBuf,
}

// Safety: The vtable function pointers are Send+Sync since they are plain C functions
// with no thread-local state. The Library handle is thread-safe for symbol resolution.
unsafe impl Send for NativePlugin {}
unsafe impl Sync for NativePlugin {}

impl NativePlugin {
    /// Load a native plugin from a shared library file.
    ///
    /// # Safety
    ///
    /// The library must export `scrypt_plugin_init` with the correct signature
    /// and the returned vtable must have a matching ABI version.
    pub fn load(path: &Path) -> Result<Self> {
        let library = unsafe {
            Library::new(path).map_err(|e| ShadowError::Plugin {
                message: format!("Failed to load native plugin {}: {e}", path.display()),
            })?
        };

        let init_fn: Symbol<PluginInitFn> = unsafe {
            library.get(b"scrypt_plugin_init").map_err(|e| ShadowError::Plugin {
                message: format!(
                    "Plugin {} missing scrypt_plugin_init symbol: {e}",
                    path.display()
                ),
            })?
        };

        let vtable_ptr = unsafe { init_fn() };
        if vtable_ptr.is_null() {
            return Err(ShadowError::Plugin {
                message: format!("Plugin {} returned null vtable", path.display()),
            });
        }

        // Safety: the vtable is expected to live for the lifetime of the library
        let vtable: &'static PluginVTable = unsafe { &*vtable_ptr };

        if vtable.abi_version != PLUGIN_ABI_VERSION {
            return Err(ShadowError::Plugin {
                message: format!(
                    "Plugin {} has ABI version {}, expected {}",
                    path.display(),
                    vtable.abi_version,
                    PLUGIN_ABI_VERSION
                ),
            });
        }

        // Get metadata
        let meta_ptr = (vtable.metadata)();
        let metadata = if meta_ptr.is_null() {
            PluginMetadata {
                name: path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".into()),
                version: "0.0.0".into(),
                author: "unknown".into(),
                description: "Native plugin".into(),
                plugin_type: PluginType::Dissector,
            }
        } else {
            let c_str = unsafe { std::ffi::CStr::from_ptr(meta_ptr) };
            let json_str = c_str.to_string_lossy();
            serde_json::from_str(&json_str).unwrap_or(PluginMetadata {
                name: path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".into()),
                version: "0.0.0".into(),
                author: "unknown".into(),
                description: "Native plugin (metadata parse failed)".into(),
                plugin_type: PluginType::Dissector,
            })
        };

        info!(
            name = %metadata.name,
            version = %metadata.version,
            path = %path.display(),
            "Loaded native plugin"
        );

        Ok(Self {
            _library: library,
            vtable,
            metadata,
            path: path.to_owned(),
        })
    }

    pub fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
}

/// Bridge a native plugin into the Dissector trait.
impl Dissector for NativePlugin {
    fn id(&self) -> DissectorId {
        DissectorId(format!("native:{}", self.metadata.name))
    }

    fn name(&self) -> &str {
        &self.metadata.name
    }

    fn can_dissect(&self, data: &[u8], _context: &DissectionContext) -> Confidence {
        let result = (self.vtable.can_dissect)(data.as_ptr(), data.len());
        match result {
            0 => Confidence::None,
            1 => Confidence::Low,
            2 => Confidence::Medium,
            3 => Confidence::High,
            4 => Confidence::Exact,
            _ => Confidence::None,
        }
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        _context: &mut DissectionContext,
    ) -> Result<DissectedLayer<'a>> {
        // Provide a buffer for the plugin to write JSON output
        let mut output_buf = vec![0u8; 64 * 1024]; // 64KB output buffer
        let consumed = (self.vtable.dissect)(
            data.as_ptr(),
            data.len(),
            output_buf.as_mut_ptr(),
            output_buf.len(),
        );

        if consumed == 0 {
            return Err(ShadowError::Plugin {
                message: format!("Native plugin {} dissect returned 0", self.metadata.name),
            });
        }

        // Find the actual JSON length (up to first null byte)
        let json_len = output_buf.iter().position(|&b| b == 0).unwrap_or(output_buf.len());
        let json_str = std::str::from_utf8(&output_buf[..json_len]).map_err(|_| {
            ShadowError::Plugin {
                message: format!(
                    "Native plugin {} returned invalid UTF-8",
                    self.metadata.name
                ),
            }
        })?;

        // Parse the output as a simple JSON structure
        #[derive(serde::Deserialize)]
        struct PluginOutput {
            protocol: String,
            summary: String,
            #[serde(default)]
            fields: Vec<PluginField>,
        }

        #[derive(serde::Deserialize)]
        struct PluginField {
            name: String,
            value: String,
        }

        let output: PluginOutput =
            serde_json::from_str(json_str).map_err(|e| ShadowError::Plugin {
                message: format!(
                    "Native plugin {} returned invalid JSON: {e}",
                    self.metadata.name
                ),
            })?;

        let fields = output
            .fields
            .into_iter()
            .map(|f| Field {
                name: f.name,
                display_value: f.value,
                byte_range: 0..0,
                field_type: FieldType::String,
            })
            .collect();

        let remaining = if consumed <= data.len() {
            &data[consumed..]
        } else {
            &data[data.len()..]
        };

        Ok(DissectedLayer {
            node: ProtocolNode {
                protocol: output.protocol,
                byte_range: 0..consumed,
                fields,
                summary: output.summary,
            },
            remaining,
            next_protocol: None,
        })
    }
}

/// Scan a directory for native plugin shared libraries and load them.
pub fn load_native_plugins(dir: &Path) -> Vec<Arc<NativePlugin>> {
    let mut plugins = Vec::new();

    let extension = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "Cannot read native plugin directory");
            return plugins;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some(extension) {
            match NativePlugin::load(&path) {
                Ok(plugin) => plugins.push(Arc::new(plugin)),
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to load native plugin");
                }
            }
        }
    }

    plugins
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_abi_version() {
        assert_eq!(PLUGIN_ABI_VERSION, 1);
    }

    #[test]
    fn test_load_nonexistent_dir() {
        let plugins = load_native_plugins(Path::new("/nonexistent/dir"));
        assert!(plugins.is_empty());
    }
}
