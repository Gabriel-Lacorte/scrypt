pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod http;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod quic;
pub mod tcp;
pub mod udp;

use crate::registry::DissectorRegistry;
use sc_core::Protocol;
use std::sync::Arc;

/// Register all built-in protocol dissectors into the registry.
pub fn register_all(registry: &mut DissectorRegistry) {
    // Link layer
    registry.register_for_protocol(Protocol::Ethernet, Arc::new(ethernet::EthernetDissector));
    registry.register_for_protocol(Protocol::Arp, Arc::new(arp::ArpDissector));

    // Network layer
    registry.register_for_protocol(Protocol::Ipv4, Arc::new(ipv4::Ipv4Dissector));
    registry.register_for_protocol(Protocol::Ipv6, Arc::new(ipv6::Ipv6Dissector));
    registry.register_for_protocol(Protocol::Icmp, Arc::new(icmp::IcmpDissector));
    registry.register_for_protocol(Protocol::Icmpv6, Arc::new(icmpv6::Icmpv6Dissector));

    // Transport layer
    registry.register_for_protocol(Protocol::Tcp, Arc::new(tcp::TcpDissector));
    registry.register_for_protocol(Protocol::Udp, Arc::new(udp::UdpDissector));

    // Application layer
    registry.register_for_protocol(Protocol::Dns, Arc::new(dns::DnsDissector));
    registry.register_for_port(53, Arc::new(dns::DnsDissector));
    registry.register_for_port(5353, Arc::new(dns::DnsDissector));

    registry.register_for_protocol(Protocol::Http, Arc::new(http::HttpDissector));
    registry.register_for_port(80, Arc::new(http::HttpDissector));
    registry.register_for_port(8080, Arc::new(http::HttpDissector));

    registry.register_for_protocol(Protocol::Quic, Arc::new(quic::QuicDissector));
    registry.register_for_port(443, Arc::new(quic::QuicDissector));
}
