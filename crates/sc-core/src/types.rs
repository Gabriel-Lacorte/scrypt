use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Direction of traffic flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

/// High-level protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Ethernet,
    Arp,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Dns,
    Http,
    Tls,
    Quic,
    Unknown(u16),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Ethernet => write!(f, "Ethernet"),
            Protocol::Arp => write!(f, "ARP"),
            Protocol::Ipv4 => write!(f, "IPv4"),
            Protocol::Ipv6 => write!(f, "IPv6"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Icmpv6 => write!(f, "ICMPv6"),
            Protocol::Dns => write!(f, "DNS"),
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Tls => write!(f, "TLS"),
            Protocol::Quic => write!(f, "QUIC"),
            Protocol::Unknown(id) => write!(f, "Unknown(0x{id:04x})"),
        }
    }
}

/// A raw packet with metadata, holding a borrowed byte slice (zero-copy).
#[derive(Debug, Clone)]
pub struct RawPacket<'a> {
    /// Packet capture timestamp
    pub timestamp: Timestamp,
    /// Captured data (may be shorter than original_len)
    pub data: &'a [u8],
    /// Original packet length on the wire
    pub original_len: u32,
    /// Link-layer type from PCAP header
    pub link_type: u32,
}

/// An owned version of RawPacket for when data must outlive the source.
#[derive(Debug, Clone)]
pub struct OwnedPacket {
    pub timestamp: Timestamp,
    pub data: Vec<u8>,
    pub original_len: u32,
    pub link_type: u32,
}

impl OwnedPacket {
    pub fn as_raw(&self) -> RawPacket<'_> {
        RawPacket {
            timestamp: self.timestamp,
            data: &self.data,
            original_len: self.original_len,
            link_type: self.link_type,
        }
    }
}

/// Timestamp with microsecond precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    /// Seconds since epoch
    pub secs: u64,
    /// Microseconds fraction
    pub micros: u32,
}

impl Timestamp {
    pub fn new(secs: u64, micros: u32) -> Self {
        Self { secs, micros }
    }

    pub fn from_system_time(time: SystemTime) -> Self {
        let since_epoch = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            secs: since_epoch.as_secs(),
            micros: since_epoch.subsec_micros(),
        }
    }

    pub fn as_duration(&self) -> Duration {
        Duration::new(self.secs, self.micros * 1000)
    }

    /// Duration between two timestamps.
    pub fn delta(&self, other: &Timestamp) -> Duration {
        let a = self.as_duration();
        let b = other.as_duration();
        if a >= b { a - b } else { b - a }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:06}", self.secs, self.micros)
    }
}

/// Network endpoint for packet addressing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: Option<u16>,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}:{}", self.addr, port),
            None => write!(f, "{}", self.addr),
        }
    }
}

/// Summary of a dissected packet for display in lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub index: usize,
    pub timestamp: Timestamp,
    pub source: String,
    pub destination: String,
    pub protocol: Protocol,
    pub length: usize,
    pub info: String,
}
