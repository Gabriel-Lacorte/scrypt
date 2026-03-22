use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level configuration for the $crypt framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub plugins: PluginsConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub mesh: MeshConfig,
    #[serde(default)]
    pub tui: TuiConfig,
    #[serde(default)]
    pub alerts: Vec<AlertRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Logging level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Output format for structured logs: "text" or "json"
    #[serde(default = "default_log_format")]
    pub log_format: String,
    /// Maximum dissection depth to prevent infinite recursion
    #[serde(default = "default_max_depth")]
    pub max_dissection_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Default network interface for live capture
    #[serde(default)]
    pub default_interface: Option<String>,
    /// Default BPF filter expression
    #[serde(default)]
    pub default_filter: Option<String>,
    /// Snapshot length for captured packets
    #[serde(default = "default_snaplen")]
    pub snaplen: u32,
    /// Buffer size for capture ring buffer in bytes
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginsConfig {
    /// Directories to scan for native plugins (.so/.dylib)
    #[serde(default = "default_plugin_dirs")]
    pub native_dirs: Vec<PathBuf>,
    /// Directories to scan for Lua scripts
    #[serde(default = "default_script_dirs")]
    pub script_dirs: Vec<PathBuf>,
    /// Enable hot-reload for Lua scripts
    #[serde(default = "default_true")]
    pub hot_reload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Enable seccomp-bpf process sandboxing
    #[serde(default = "default_true")]
    pub enable_seccomp: bool,
    /// Enable landlock filesystem isolation
    #[serde(default = "default_true")]
    pub enable_landlock: bool,
    /// Allowed output directory for writes
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// gRPC listen address for mesh node
    #[serde(default = "default_mesh_addr")]
    pub listen_addr: String,
    /// Known peer addresses for mesh discovery
    #[serde(default)]
    pub peers: Vec<String>,
    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuiConfig {
    /// Color theme: "dark", "light"
    #[serde(default = "default_theme")]
    pub theme: String,
    /// Refresh rate in milliseconds
    #[serde(default = "default_refresh_rate")]
    pub refresh_rate_ms: u64,
}

/// An alert rule that flags matching packets in the TUI and analysis output.
///
/// Alert rules are evaluated against each dissected packet. When matched, the
/// packet is highlighted in the TUI and the alert message is included in
/// structured output.
///
/// # Configuration Example
///
/// ```toml
/// [[alerts]]
/// name = "suspicious-port"
/// filter = "port:4444"
/// severity = "high"
/// message = "Connection to suspicious port 4444"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Human-readable rule name.
    pub name: String,
    /// Filter expression (same syntax as TUI display filter).
    pub filter: String,
    /// Severity level: "info", "warning", "high", "critical".
    #[serde(default = "default_alert_severity")]
    pub severity: String,
    /// Message displayed when the rule matches.
    pub message: String,
}

// Default value functions

fn default_log_level() -> String {
    "info".into()
}

fn default_log_format() -> String {
    "text".into()
}

fn default_max_depth() -> usize {
    16
}

fn default_snaplen() -> u32 {
    65535
}

fn default_buffer_size() -> usize {
    16 * 1024 * 1024 // 16 MB
}

fn default_plugin_dirs() -> Vec<PathBuf> {
    vec![PathBuf::from("plugins/builtins")]
}

fn default_script_dirs() -> Vec<PathBuf> {
    vec![PathBuf::from("plugins/scripts")]
}

fn default_true() -> bool {
    true
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("output")
}

fn default_mesh_addr() -> String {
    "[::1]:50051".into()
}

fn default_heartbeat() -> u64 {
    10
}

fn default_theme() -> String {
    "dark".into()
}

fn default_refresh_rate() -> u64 {
    100
}

fn default_alert_severity() -> String {
    "info".into()
}

impl Default for Config {
    fn default() -> Self {
        toml::from_str("").expect("default config must parse")
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            log_format: default_log_format(),
            max_dissection_depth: default_max_depth(),
        }
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            default_interface: None,
            default_filter: None,
            snaplen: default_snaplen(),
            buffer_size: default_buffer_size(),
        }
    }
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            native_dirs: default_plugin_dirs(),
            script_dirs: default_script_dirs(),
            hot_reload: true,
        }
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enable_seccomp: true,
            enable_landlock: true,
            output_dir: default_output_dir(),
        }
    }
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_mesh_addr(),
            peers: Vec::new(),
            heartbeat_interval_secs: default_heartbeat(),
        }
    }
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            refresh_rate_ms: default_refresh_rate(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file, falling back to defaults.
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| crate::ShadowError::Config {
            message: format!("failed to read config file {}: {e}", path.display()),
        })?;
        toml::from_str(&content).map_err(|e| crate::ShadowError::Config {
            message: format!("failed to parse config: {e}"),
        })
    }

    /// Load from a path if it exists, otherwise return defaults.
    pub fn load_or_default(path: &std::path::Path) -> Self {
        if path.exists() {
            Self::load(path).unwrap_or_default()
        } else {
            Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.general.log_level, "info");
        assert_eq!(cfg.general.max_dissection_depth, 16);
        assert_eq!(cfg.capture.snaplen, 65535);
        assert!(cfg.plugins.hot_reload);
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml_str = r#"
[general]
log_level = "debug"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.general.log_level, "debug");
        assert_eq!(cfg.general.max_dissection_depth, 16); // default
    }
}
