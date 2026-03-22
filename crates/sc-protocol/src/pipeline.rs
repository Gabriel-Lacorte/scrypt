use crate::dissector::DissectionContext;
use crate::model::DissectionTree;
use crate::registry::SharedRegistry;
use sc_core::Protocol;
use tracing::{debug, trace};

/// The dissection pipeline that processes a raw packet through registered dissectors.
pub struct Pipeline {
    registry: SharedRegistry,
    max_depth: usize,
}

impl Pipeline {
    pub fn new(registry: SharedRegistry, max_depth: usize) -> Self {
        Self {
            registry,
            max_depth,
        }
    }

    /// Dissect a raw packet, producing a complete DissectionTree.
    /// Assumes Ethernet link layer by default.
    pub fn dissect(&self, packet: &[u8]) -> DissectionTree {
        self.dissect_with_link_type(packet, Protocol::Ethernet)
    }

    /// Dissect a raw packet starting from the specified link-layer protocol.
    pub fn dissect_with_link_type(&self, packet: &[u8], link_protocol: Protocol) -> DissectionTree {
        let mut ctx = DissectionContext::new(self.max_depth);
        ctx.next_protocol_hint = Some(link_protocol);

        let mut remaining = packet;

        let registry = self.registry.read().expect("registry lock poisoned");

        while !remaining.is_empty() && !ctx.depth_exceeded() {
            let dissector = match registry.find_best(remaining, &ctx) {
                Some(d) => d,
                None => {
                    trace!(
                        bytes_remaining = remaining.len(),
                        "No dissector found for remaining data"
                    );
                    break;
                }
            };

            debug!(
                dissector = dissector.name(),
                depth = ctx.depth,
                bytes = remaining.len(),
                "Dissecting layer"
            );

            match dissector.dissect(remaining, &mut ctx) {
                Ok(layer) => {
                    ctx.tree.push_layer(layer.node);
                    ctx.next_protocol_hint = layer.next_protocol;
                    remaining = layer.remaining;
                    ctx.depth += 1;
                }
                Err(e) => {
                    debug!(error = %e, dissector = dissector.name(), "Dissector failed");
                    break;
                }
            }
        }

        ctx.tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins;
    use crate::registry::new_shared_registry;

    #[test]
    fn test_pipeline_ethernet_ipv4_tcp() {
        let registry = new_shared_registry();
        builtins::register_all(&mut registry.write().unwrap());

        let pipeline = Pipeline::new(registry, 16);

        // Construct a minimal Ethernet + IPv4 + TCP packet
        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            // Ethernet header (14 bytes)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // dst MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src MAC
            0x08, 0x00,                            // EtherType: IPv4
            // IPv4 header (20 bytes, no options)
            0x45, 0x00, 0x00, 0x28,  // version/IHL, DSCP, total length=40
            0x00, 0x01, 0x00, 0x00,  // ID, flags/offset
            0x40, 0x06, 0x00, 0x00,  // TTL=64, protocol=TCP, checksum
            0xc0, 0xa8, 0x01, 0x01,  // src IP: 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02,  // dst IP: 192.168.1.2
            // TCP header (20 bytes, no options)
            0x00, 0x50, 0xc0, 0x00,  // src port=80, dst port=49152
            0x00, 0x00, 0x00, 0x01,  // seq number
            0x00, 0x00, 0x00, 0x00,  // ack number
            0x50, 0x02, 0xff, 0xff,  // data offset=5, SYN flag, window
            0x00, 0x00, 0x00, 0x00,  // checksum, urgent pointer
        ];

        let tree = pipeline.dissect(&packet);
        assert_eq!(tree.layers.len(), 3);
        assert_eq!(tree.layers[0].protocol, "Ethernet");
        assert_eq!(tree.layers[1].protocol, "IPv4");
        assert_eq!(tree.layers[2].protocol, "TCP");
    }
}
