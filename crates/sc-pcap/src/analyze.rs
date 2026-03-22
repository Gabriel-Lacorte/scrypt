use rayon::prelude::*;
use sc_core::OwnedPacket;
use sc_protocol::{DissectionTree, Pipeline, SharedRegistry};

/// An analyzed packet with both raw data and dissection results.
#[derive(Debug, Clone)]
pub struct AnalyzedPacket {
    pub index: usize,
    pub packet: OwnedPacket,
    pub tree: DissectionTree,
}

/// Combines PCAP reading with protocol dissection.
pub struct PcapAnalyzer {
    pipeline: Pipeline,
}

impl PcapAnalyzer {
    pub fn new(registry: SharedRegistry, max_depth: usize) -> Self {
        Self {
            pipeline: Pipeline::new(registry, max_depth),
        }
    }

    /// Analyze a single packet.
    pub fn analyze_one(&self, index: usize, packet: &OwnedPacket) -> AnalyzedPacket {
        let tree = self.pipeline.dissect(&packet.data);
        AnalyzedPacket {
            index,
            packet: packet.clone(),
            tree,
        }
    }

    /// Analyze all packets in parallel using rayon.
    pub fn analyze_all(&self, packets: &[OwnedPacket]) -> Vec<AnalyzedPacket> {
        packets
            .par_iter()
            .enumerate()
            .map(|(i, pkt)| self.analyze_one(i, pkt))
            .collect()
    }
}
