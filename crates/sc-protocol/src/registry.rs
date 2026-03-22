use crate::dissector::{Confidence, DissectionContext, Dissector, DissectorId};
use sc_core::Protocol;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::debug;

/// Registry that maps protocol hints and port numbers to dissectors.
pub struct DissectorRegistry {
    /// Dissectors indexed by protocol hint
    by_protocol: HashMap<Protocol, Vec<Arc<dyn Dissector>>>,
    /// Dissectors indexed by TCP/UDP port
    by_port: HashMap<u16, Vec<Arc<dyn Dissector>>>,
    /// All registered dissectors by ID
    all: HashMap<DissectorId, Arc<dyn Dissector>>,
}

impl DissectorRegistry {
    pub fn new() -> Self {
        Self {
            by_protocol: HashMap::new(),
            by_port: HashMap::new(),
            all: HashMap::new(),
        }
    }

    /// Register a dissector for a specific protocol hint.
    pub fn register_for_protocol(&mut self, protocol: Protocol, dissector: Arc<dyn Dissector>) {
        debug!("Registering dissector {} for protocol {:?}", dissector.id(), protocol);
        self.all.insert(dissector.id(), Arc::clone(&dissector));
        self.by_protocol.entry(protocol).or_default().push(dissector);
    }

    /// Register a dissector for a specific port number.
    pub fn register_for_port(&mut self, port: u16, dissector: Arc<dyn Dissector>) {
        debug!("Registering dissector {} for port {}", dissector.id(), port);
        self.all.insert(dissector.id(), Arc::clone(&dissector));
        self.by_port.entry(port).or_default().push(dissector);
    }

    /// Find the best matching dissector for the given data and context.
    pub fn find_best(
        &self,
        data: &[u8],
        context: &DissectionContext,
    ) -> Option<Arc<dyn Dissector>> {
        let mut candidates: Vec<(Confidence, Arc<dyn Dissector>)> = Vec::new();

        // Collect candidates from protocol hint
        if let Some(hint) = &context.next_protocol_hint {
            if let Some(dissectors) = self.by_protocol.get(hint) {
                for d in dissectors {
                    let conf = d.can_dissect(data, context);
                    if conf > Confidence::None {
                        candidates.push((conf, Arc::clone(d)));
                    }
                }
            }
        }

        // Collect candidates from port numbers
        for port in [context.src_port, context.dst_port].iter().flatten() {
            if let Some(dissectors) = self.by_port.get(port) {
                for d in dissectors {
                    // Avoid duplicates
                    if candidates.iter().any(|(_, existing)| existing.id() == d.id()) {
                        continue;
                    }
                    let conf = d.can_dissect(data, context);
                    if conf > Confidence::None {
                        candidates.push((conf, Arc::clone(d)));
                    }
                }
            }
        }

        // If no candidates found via hints, try all dissectors
        if candidates.is_empty() {
            for (_, d) in &self.all {
                let conf = d.can_dissect(data, context);
                if conf > Confidence::None {
                    candidates.push((conf, Arc::clone(d)));
                }
            }
        }

        // Return highest confidence
        candidates.sort_by(|a, b| b.0.cmp(&a.0));
        candidates.into_iter().next().map(|(_, d)| d)
    }

    /// Get a dissector by its ID.
    pub fn get(&self, id: &DissectorId) -> Option<Arc<dyn Dissector>> {
        self.all.get(id).cloned()
    }

    /// List all registered dissector IDs.
    pub fn list_ids(&self) -> Vec<DissectorId> {
        self.all.keys().cloned().collect()
    }
}

impl Default for DissectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe shared registry.
pub type SharedRegistry = Arc<RwLock<DissectorRegistry>>;

pub fn new_shared_registry() -> SharedRegistry {
    Arc::new(RwLock::new(DissectorRegistry::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissector::DissectedLayer;
    use crate::model::ProtocolNode;

    struct DummyDissector;
    impl Dissector for DummyDissector {
        fn id(&self) -> DissectorId { DissectorId("dummy".into()) }
        fn name(&self) -> &str { "Dummy" }
        fn can_dissect(&self, _data: &[u8], _ctx: &DissectionContext) -> Confidence {
            Confidence::High
        }
        fn dissect<'a>(&self, data: &'a [u8], _ctx: &mut DissectionContext) -> sc_core::Result<DissectedLayer<'a>> {
            Ok(DissectedLayer {
                node: ProtocolNode {
                    protocol: "Dummy".into(),
                    byte_range: 0..data.len(),
                    fields: vec![],
                    summary: "Dummy protocol".into(),
                },
                remaining: &[],
                next_protocol: None,
            })
        }
    }

    #[test]
    fn test_registry_find_by_protocol() {
        let mut reg = DissectorRegistry::new();
        reg.register_for_protocol(Protocol::Ethernet, Arc::new(DummyDissector));

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Ethernet);
        let found = reg.find_best(&[0u8; 14], &ctx);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "Dummy");
    }
}
