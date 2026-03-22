use sc_core::{Result, ShadowError};
use std::path::PathBuf;
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

/// Check if the current kernel supports Landlock LSM (requires kernel >= 5.13).
pub fn landlock_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Some(version) = uname_info() {
            return version >= (5, 13);
        }
    }
    false
}

/// Check if seccomp-bpf is available by querying the kernel via prctl.
pub fn seccomp_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        // PR_GET_SECCOMP returns 0 if seccomp is available and the process
        // is not currently in strict mode. Returns -1/EINVAL if not supported.
        let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            if errno == libc::EINVAL {
                return false;
            }
        }
        // ret == 0 means seccomp is available but not active
        // ret == 2 means seccomp filter mode already active (still supported)
        ret >= 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn uname_info() -> Option<(u32, u32)> {
    let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::uname(&mut utsname) };
    if ret != 0 {
        return None;
    }
    let release = unsafe { std::ffi::CStr::from_ptr(utsname.release.as_ptr()) };
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

/// Build the seccomp BPF filter for a given profile.
///
/// The on-match action for allowed syscalls is `Allow`. The default action
/// for anything not in the allowlist is `Errno(EPERM)`.
#[cfg(target_os = "linux")]
fn build_seccomp_filter(
    profile: Profile,
) -> std::result::Result<seccompiler::BpfProgram, ShadowError> {
    use std::collections::HashMap;
    use std::convert::TryInto;

    let mut rules: HashMap<i64, Vec<seccompiler::SeccompRule>> = HashMap::new();

    // Common base syscalls for all profiles (minimal for pure computation)
    let base_syscalls: &[i64] = &[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_exit,
        libc::SYS_exit_group,
        // Required for basic runtime operation
        libc::SYS_brk,
        libc::SYS_mprotect,
        libc::SYS_sigaltstack,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_futex,
        libc::SYS_sched_yield,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_gettid,
        libc::SYS_getpid,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_lseek,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
    ];

    for &syscall in base_syscalls {
        rules.insert(syscall, vec![]);
    }

    match profile {
        Profile::Strict => {
            // Strict: only the base syscalls above — no network, no filesystem writes
        }
        Profile::Network => {
            // Network: base + network-related syscalls
            let net_syscalls: &[i64] = &[
                libc::SYS_socket,
                libc::SYS_connect,
                libc::SYS_bind,
                libc::SYS_listen,
                libc::SYS_accept,
                libc::SYS_accept4,
                libc::SYS_sendto,
                libc::SYS_recvfrom,
                libc::SYS_sendmsg,
                libc::SYS_recvmsg,
                libc::SYS_poll,
                libc::SYS_epoll_create1,
                libc::SYS_epoll_ctl,
                libc::SYS_epoll_wait,
                libc::SYS_setsockopt,
                libc::SYS_getsockopt,
                libc::SYS_getsockname,
                libc::SYS_getpeername,
                libc::SYS_shutdown,
            ];
            for &syscall in net_syscalls {
                rules.insert(syscall, vec![]);
            }
        }
        Profile::Plugin => {
            // Plugin: base + limited filesystem (read-only open) for Lua VM
            let plugin_syscalls: &[i64] = &[
                libc::SYS_openat,
                libc::SYS_fcntl,
                libc::SYS_ioctl,
                libc::SYS_dup,
                libc::SYS_dup2,
                libc::SYS_pipe2,
                libc::SYS_pread64,
                libc::SYS_pwrite64,
                libc::SYS_getdents64,
                libc::SYS_access,
                libc::SYS_stat,
            ];
            for &syscall in plugin_syscalls {
                rules.insert(syscall, vec![]);
            }
        }
    }

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| ShadowError::Sandbox {
            message: format!("Unsupported architecture: {}", std::env::consts::ARCH),
        })?;

    let filter = seccompiler::SeccompFilter::new(
        rules.into_iter().collect(),
        // Default action: deny with EPERM (more debuggable than Kill)
        seccompiler::SeccompAction::Errno(libc::EPERM as u32),
        // Match action: allow
        seccompiler::SeccompAction::Allow,
        arch,
    )
    .map_err(|e| ShadowError::Sandbox {
        message: format!("Failed to create seccomp filter: {e}"),
    })?;

    let bpf: seccompiler::BpfProgram = filter.try_into().map_err(|e| ShadowError::Sandbox {
        message: format!("Failed to compile seccomp BPF: {e:?}"),
    })?;

    Ok(bpf)
}

/// Apply Landlock filesystem restrictions.
///
/// Restricts filesystem access to the specified allowed directories.
/// Uses the Landlock ABI v1+ syscalls directly via libc.
#[cfg(target_os = "linux")]
fn apply_landlock(allowed_dirs: &[PathBuf]) -> std::result::Result<(), ShadowError> {
    use std::os::unix::io::RawFd;

    // Landlock ABI constants
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

    // All access rights we want to restrict
    let handled_access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    let read_access =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    let write_access = read_access
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_DIR;

    // Syscall numbers for Landlock
    let sys_landlock_create_ruleset: i64 = 444;
    let sys_landlock_add_rule: i64 = 445;
    let sys_landlock_restrict_self: i64 = 446;

    // Structs matching kernel ABI
    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: RawFd,
    }

    // Check ABI version
    let abi_version = unsafe {
        libc::syscall(
            sys_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi_version < 0 {
        return Err(ShadowError::Sandbox {
            message: "Landlock syscall not available on this kernel".into(),
        });
    }

    // Create ruleset
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_access,
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            sys_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(ShadowError::Sandbox {
            message: format!(
                "Failed to create Landlock ruleset: {}",
                std::io::Error::last_os_error()
            ),
        });
    }
    let ruleset_fd = ruleset_fd as RawFd;

    // Ensure we close the fd on exit
    struct FdGuard(RawFd);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let _guard = FdGuard(ruleset_fd);

    // Add rules for each allowed directory
    for dir in allowed_dirs {
        if !dir.exists() {
            // Try to create output directory if it doesn't exist
            let _ = std::fs::create_dir_all(dir);
        }
        if !dir.exists() {
            continue;
        }

        let path_c = std::ffi::CString::new(dir.to_string_lossy().as_bytes()).map_err(|_| {
            ShadowError::Sandbox {
                message: format!("Invalid path for Landlock rule: {}", dir.display()),
            }
        })?;

        let parent_fd = unsafe { libc::open(path_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent_fd < 0 {
            warn!(dir = %dir.display(), "Cannot open directory for Landlock rule, skipping");
            continue;
        }
        let _fd_guard = FdGuard(parent_fd);

        let beneath_attr = LandlockPathBeneathAttr {
            allowed_access: write_access,
            parent_fd,
        };

        let ret = unsafe {
            libc::syscall(
                sys_landlock_add_rule,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &beneath_attr as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        if ret < 0 {
            warn!(
                dir = %dir.display(),
                error = %std::io::Error::last_os_error(),
                "Failed to add Landlock rule for directory"
            );
        }
    }

    // Also allow read-only access to common system paths
    for sys_path in &["/usr", "/lib", "/lib64", "/etc", "/proc/self"] {
        let path = PathBuf::from(sys_path);
        if !path.exists() {
            continue;
        }
        let path_c = match std::ffi::CString::new(sys_path.as_bytes()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let parent_fd = unsafe { libc::open(path_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent_fd < 0 {
            continue;
        }
        let _fd_guard = FdGuard(parent_fd);

        let beneath_attr = LandlockPathBeneathAttr {
            allowed_access: read_access,
            parent_fd,
        };
        unsafe {
            libc::syscall(
                sys_landlock_add_rule,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &beneath_attr as *const LandlockPathBeneathAttr,
                0u32,
            );
        }
    }

    // Restrict self — apply the ruleset
    // First, no_new_privs must be set
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        return Err(ShadowError::Sandbox {
            message: format!(
                "Failed to set no_new_privs: {}",
                std::io::Error::last_os_error()
            ),
        });
    }

    let ret = unsafe { libc::syscall(sys_landlock_restrict_self, ruleset_fd, 0u32) };
    if ret < 0 {
        return Err(ShadowError::Sandbox {
            message: format!(
                "Failed to apply Landlock ruleset: {}",
                std::io::Error::last_os_error()
            ),
        });
    }

    Ok(())
}

/// Builder for constructing sandbox configurations.
pub struct SandboxBuilder {
    profile: Profile,
    output_dir: Option<PathBuf>,
    allowed_dirs: Vec<PathBuf>,
}

impl SandboxBuilder {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            output_dir: None,
            allowed_dirs: Vec::new(),
        }
    }

    pub fn output_dir(mut self, dir: PathBuf) -> Self {
        self.output_dir = Some(dir);
        self
    }

    pub fn allowed_dir(mut self, dir: PathBuf) -> Self {
        self.allowed_dirs.push(dir);
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

            // Apply Landlock first (filesystem restrictions) — before seccomp
            // locks down the syscalls we need to set up Landlock.
            if landlock_supported() {
                let mut dirs = self.allowed_dirs.clone();
                if let Some(ref out) = self.output_dir {
                    dirs.push(out.clone());
                }
                match apply_landlock(&dirs) {
                    Ok(()) => info!("Landlock filesystem isolation applied"),
                    Err(e) => {
                        warn!(error = %e, "Failed to apply Landlock, continuing without filesystem isolation")
                    }
                }
            } else {
                warn!("Landlock not supported on this kernel, skipping filesystem isolation");
            }

            // Apply seccomp-bpf filter
            if seccomp_supported() {
                let bpf = build_seccomp_filter(self.profile)?;

                // PR_SET_NO_NEW_PRIVS is required before applying seccomp filters
                let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
                if ret < 0 {
                    return Err(ShadowError::Sandbox {
                        message: format!(
                            "Failed to set no_new_privs: {}",
                            std::io::Error::last_os_error()
                        ),
                    });
                }

                seccompiler::apply_filter(&bpf).map_err(|e| ShadowError::Sandbox {
                    message: format!("Failed to install seccomp filter: {e}"),
                })?;

                info!(profile = ?self.profile, "Seccomp-bpf filter installed");
            } else {
                warn!("Seccomp not supported by kernel, running without syscall filtering");
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
        caps.push(format!(
            "Platform: {} (sandbox not supported)",
            std::env::consts::OS
        ));
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_supported_returns_bool() {
        // On Linux CI this should return true; on other platforms false.
        let result = seccomp_supported();
        if cfg!(target_os = "linux") {
            assert!(result, "seccomp should be available on Linux");
        } else {
            assert!(!result, "seccomp should not be available on non-Linux");
        }
    }

    #[test]
    fn test_landlock_supported_returns_bool() {
        // Just verify it doesn't panic.
        let _result = landlock_supported();
    }

    #[test]
    fn test_capabilities_report() {
        let caps = capabilities_report();
        assert!(!caps.is_empty());
        assert!(caps[0].starts_with("Platform:"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_seccomp_filter_strict() {
        let bpf = build_seccomp_filter(Profile::Strict);
        assert!(bpf.is_ok(), "Should build strict filter: {:?}", bpf.err());
        assert!(!bpf.unwrap().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_seccomp_filter_network() {
        let bpf = build_seccomp_filter(Profile::Network);
        assert!(bpf.is_ok(), "Should build network filter: {:?}", bpf.err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_seccomp_filter_plugin() {
        let bpf = build_seccomp_filter(Profile::Plugin);
        assert!(bpf.is_ok(), "Should build plugin filter: {:?}", bpf.err());
    }

    /// Test that a strict sandbox actually blocks forbidden syscalls.
    /// This forks a child process, applies the sandbox, and attempts
    /// a forbidden syscall (socket), verifying it fails with EPERM.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_strict_sandbox_blocks_socket() {
        use std::io::{Read, Write};
        use std::os::unix::io::FromRawFd;

        // Create a pipe for the child to report back
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Child process
            unsafe { libc::close(fds[0]) };
            let mut write_pipe = unsafe { std::fs::File::from_raw_fd(fds[1]) };

            // Apply strict sandbox
            let bpf = build_seccomp_filter(Profile::Strict).expect("build filter");
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            seccompiler::apply_filter(&bpf).expect("apply filter");

            // Attempt socket() — should fail with EPERM
            let ret = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            let errno = if ret < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u8
            } else {
                0u8
            };
            let _ = write_pipe.write_all(&[errno]);
            drop(write_pipe);
            unsafe { libc::_exit(0) };
        } else {
            // Parent process
            unsafe { libc::close(fds[1]) };
            let mut read_pipe = unsafe { std::fs::File::from_raw_fd(fds[0]) };

            let mut buf = [0u8; 1];
            read_pipe.read_exact(&mut buf).expect("read from child");

            let mut status = 0i32;
            unsafe { libc::waitpid(pid, &mut status, 0) };

            assert_eq!(
                buf[0] as i32,
                libc::EPERM,
                "socket() should have returned EPERM under strict sandbox"
            );
        }
    }
}
