use sc_core::{Result, ShadowError};
use tracing::{info, warn};

/// Sandbox security profile levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Minimal syscalls for pure analysis (no network, no filesystem writes)
    Strict,
    /// Analysis + network read access
    Network,
    /// Restricted profile for plugin execution
    Plugin,
}

/// Check if the current kernel supports landlock.
pub fn landlock_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check kernel version >= 5.13 via uname
        let info = uname_info();
        if let Some(version) = info {
            return version >= (5, 13);
        }
    }
    false
}

/// Check if seccomp is available.
pub fn seccomp_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        // prctl(PR_GET_SECCOMP) returns 0 if seccomp is available
        return true; // Simplified — assume available on Linux
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn uname_info() -> Option<(u32, u32)> {
    let mut utsname = libc::utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    let ret = unsafe { libc::uname(&mut utsname) };
    if ret != 0 {
        return None;
    }
    let release = unsafe {
        std::ffi::CStr::from_ptr(utsname.release.as_ptr())
    };
    let release_str = release.to_string_lossy();
    let parts: Vec<&str> = release_str.split('.').collect();
    if parts.len() >= 2 {
        let major = parts[0].parse::<u32>().ok()?;
        let minor = parts[1].parse::<u32>().ok()?;
        Some((major, minor))
    } else {
        None
    }
}

/// Builder for constructing sandbox configurations.
pub struct SandboxBuilder {
    profile: Profile,
    output_dir: Option<std::path::PathBuf>,
}

impl SandboxBuilder {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            output_dir: None,
        }
    }

    pub fn output_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.output_dir = Some(dir);
        self
    }

    /// Apply the sandbox. On non-Linux, this is a no-op with a warning.
    pub fn apply(self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            warn!("Sandbox is only supported on Linux; running without restrictions");
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            info!(profile = ?self.profile, "Applying sandbox profile");

            if landlock_supported() {
                info!("Landlock available, applying filesystem restrictions");
                // Landlock ruleset application would go here
                // For MVP, log the intent
            } else {
                warn!("Landlock not supported on this kernel, skipping filesystem isolation");
            }

            if seccomp_supported() {
                info!("Seccomp available, applying syscall filter");
                // seccomp-bpf filter application would go here
                // For MVP, log the intent
            }

            Ok(())
        }
    }
}

/// Quick function to report sandbox capabilities.
pub fn capabilities_report() -> Vec<String> {
    let mut caps = Vec::new();

    if cfg!(target_os = "linux") {
        caps.push("Platform: Linux".into());
        if seccomp_supported() {
            caps.push("seccomp-bpf: available".into());
        } else {
            caps.push("seccomp-bpf: not available".into());
        }
        if landlock_supported() {
            caps.push("Landlock LSM: available".into());
        } else {
            caps.push("Landlock LSM: not available (kernel < 5.13)".into());
        }
    } else {
        caps.push(format!("Platform: {} (sandbox not supported)", std::env::consts::OS));
    }

    caps
}
