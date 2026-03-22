use crate::model::{DissectionTree, ProtocolNode};
use sc_core::Protocol;
use std::fmt;

/// Confidence level for protocol identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    None,
    Low,
    Medium,
    High,
    Exact,
}

/// Context passed through the dissection pipeline, accumulating state.
#[derive(Debug, Clone)]
pub struct DissectionContext {
    /// Hint about the next expected protocol (from parent layer)
    pub next_protocol_hint: Option<Protocol>,
    /// Source port (if known from transport layer)
    pub src_port: Option<u16>,
    /// Destination port (if known from transport layer)
    pub dst_port: Option<u16>,
    /// Current dissection depth
    pub depth: usize,
    /// Maximum allowed depth
    pub max_depth: usize,
    /// The tree being built (accumulated layers)
    pub tree: DissectionTree,
}

impl DissectionContext {
    pub fn new(max_depth: usize) -> Self {
        Self {
            next_protocol_hint: None,
            src_port: None,
            dst_port: None,
            depth: 0,
            max_depth,
            tree: DissectionTree::new(),
        }
    }

    /// Check if we've exceeded the maximum dissection depth.
    pub fn depth_exceeded(&self) -> bool {
        self.depth >= self.max_depth
    }
}

/// Result of dissecting a single layer.
pub struct DissectedLayer<'a> {
    /// The protocol node containing parsed fields
    pub node: ProtocolNode,
    /// Remaining unparsed payload (borrowed from original packet data)
    pub remaining: &'a [u8],
    /// Hint for which protocol the payload contains
    pub next_protocol: Option<Protocol>,
}

/// Unique identifier for a registered dissector.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DissectorId(pub String);

impl fmt::Display for DissectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The core trait that all protocol dissectors must implement.
pub trait Dissector: Send + Sync {
    /// Unique identifier for this dissector.
    fn id(&self) -> DissectorId;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Check if this dissector can handle the given data in the current context.
    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence;

    /// Dissect the data, producing a protocol node and remaining payload.
    fn dissect<'a>(
        &self,
        data: &'a [u8],
        context: &mut DissectionContext,
    ) -> sc_core::Result<DissectedLayer<'a>>;
}
