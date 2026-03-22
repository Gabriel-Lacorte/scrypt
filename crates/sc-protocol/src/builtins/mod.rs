pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

use crate::registry::DissectorRegistry;
use sc_core::Protocol;
use std::sync::Arc;

/// Register all built-in protocol dissectors into the registry.
pub fn register_all(registry: &mut DissectorRegistry) {
    // Ethernet
    registry.register_for_protocol(Protocol::Ethernet, Arc::new(ethernet::EthernetDissector));

    // Network layer
    registry.register_for_protocol(Protocol::Ipv4, Arc::new(ipv4::Ipv4Dissector));
    registry.register_for_protocol(Protocol::Ipv6, Arc::new(ipv6::Ipv6Dissector));

    // Transport layer
    registry.register_for_protocol(Protocol::Tcp, Arc::new(tcp::TcpDissector));
    registry.register_for_protocol(Protocol::Udp, Arc::new(udp::UdpDissector));
}
