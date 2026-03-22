# Changelog

All notable changes to $crypt are documented here.

## [Unreleased]

### Added
- **sc-sandbox**: Real seccomp-BPF syscall filtering with Strict/Network/Plugin profiles
- **sc-sandbox**: Landlock LSM filesystem isolation with allowed directory lists
- **sc-sandbox**: `SandboxBuilder` for composable sandbox configuration
- **sc-crypto**: X25519 Diffie-Hellman key exchange via `x25519-dalek`
- **sc-crypto**: Full TLS 1.3 key schedule (RFC 8446 §7.1) — HKDF-Expand-Label, derive_secret, derive_traffic_keys
- **sc-tls**: ClientHello/ServerHello parsing with SNI, ALPN, supported_versions extraction
- **sc-tls**: X.509 certificate parsing (subject, issuer, SANs, fingerprint)
- **sc-tls**: SSLKEYLOGFILE reader (NSS format) for traffic decryption
- **sc-tls**: TLS 1.3 record decryption (AES-256-GCM, ChaCha20-Poly1305)
- **sc-plugin**: Native plugin loader via `libloading` with C ABI vtable interface
- **sc-plugin**: `NativePlugin` bridge implementing `Dissector` trait over FFI
- **sc-mesh**: Full gRPC mesh service (JoinMesh, Heartbeat, SubmitTask, GetResults)
- **sc-mesh**: Peer state tracking with heartbeat-based eviction
- **sc-mesh**: Automatic peer discovery via JoinMesh known_peers exchange
- **sc-tui**: BPF-style display filters (`tcp`, `port:443`, `ip.src==10.0.0.1`, `field:value`)
- **sc-tui**: Hex dump scrolling with j/k navigation
- **sc-tui**: Status bar showing active pane, packet count, and keybindings
- **sc-tui**: Configurable `Theme` struct for UI colors
- GitHub Actions CI (build, test, clippy, format)
- `justfile` for common development commands

### Changed
- **sc-tui**: Replaced deprecated `highlight_style()` with `row_highlight_style()`
- **sc-tui**: Extracted address helper and filter logic to free functions

### Fixed
- Eliminated all compiler warnings across the workspace (52 tests, 0 warnings)
