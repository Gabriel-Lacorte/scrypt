use sc_core::{OwnedPacket, Result};

/// Trait for live network packet capture.
///
/// Implementations may use libpcap, AF_PACKET sockets, or other platform-specific
/// mechanisms. This trait defines the interface; actual backends will be provided
/// in future releases.
///
/// # Example (future)
///
/// ```ignore
/// let capture = PcapLiveCapture::new("eth0", "tcp port 443")?;
/// capture.start(|packet| {
///     println!("Got packet: {} bytes", packet.data.len());
/// })?;
/// ```
pub trait LiveCapture: Send {
    /// Start capturing packets on the given interface.
    ///
    /// `interface` is the network interface name (e.g., "eth0", "lo").
    /// `bpf_filter` is an optional BPF filter expression (e.g., "tcp port 443").
    /// `callback` is invoked for each captured packet.
    fn start<F>(&self, interface: &str, bpf_filter: Option<&str>, callback: F) -> Result<()>
    where
        F: FnMut(OwnedPacket) + Send + 'static;

    /// Stop an active capture session.
    fn stop(&self) -> Result<()>;

    /// List available network interfaces.
    fn list_interfaces(&self) -> Result<Vec<String>>;
}
