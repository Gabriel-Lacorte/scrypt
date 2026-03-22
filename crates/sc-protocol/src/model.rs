use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Range;

/// A node in the protocol dissection tree, representing one parsed protocol layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolNode {
    /// Protocol identifier name (e.g. "Ethernet", "IPv4", "TCP")
    pub protocol: String,
    /// Byte range within the original packet that this layer spans
    pub byte_range: Range<usize>,
    /// Parsed fields within this layer
    pub fields: Vec<Field>,
    /// Summary info string for display
    pub summary: String,
}

/// A parsed field within a protocol layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    /// Human-readable field name
    pub name: String,
    /// Displayed value (formatted)
    pub display_value: String,
    /// Byte range within the original packet
    pub byte_range: Range<usize>,
    /// Semantic type of this field
    pub field_type: FieldType,
}

/// Semantic type of a protocol field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    UInt8,
    UInt16,
    UInt32,
    Bytes,
    MacAddress,
    Ipv4Address,
    Ipv6Address,
    String,
    Flags(Vec<(String, bool)>),
    Enum { value: u32, label: String },
}

/// The full dissection result for a single packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectionTree {
    /// Ordered list of protocol layers (outermost first)
    pub layers: Vec<ProtocolNode>,
    /// The highest (most specific) protocol identified
    pub top_protocol: String,
}

impl DissectionTree {
    pub fn new() -> Self {
        Self {
            layers: Vec::new(),
            top_protocol: String::from("Unknown"),
        }
    }

    pub fn push_layer(&mut self, node: ProtocolNode) {
        self.top_protocol = node.protocol.clone();
        self.layers.push(node);
    }

    /// Render the tree as a human-readable hierarchical text.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for (i, layer) in self.layers.iter().enumerate() {
            let indent = "  ".repeat(i);
            out.push_str(&format!(
                "{indent}▶ {} [bytes {}..{}]\n",
                layer.protocol, layer.byte_range.start, layer.byte_range.end
            ));
            out.push_str(&format!("{indent}  {}\n", layer.summary));
            for field in &layer.fields {
                out.push_str(&format!(
                    "{indent}    {}: {}\n",
                    field.name, field.display_value
                ));
            }
        }
        out
    }
}

impl Default for DissectionTree {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DissectionTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_text())
    }
}

/// Format a MAC address from 6 bytes.
pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() >= 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    } else {
        String::from("??:??:??:??:??:??")
    }
}

/// Generate a hex dump with ASCII sidebar.
pub fn hex_dump(data: &[u8], offset: usize) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = offset + i * 16;
        out.push_str(&format!("{addr:08x}  "));

        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                out.push(' ');
            }
            out.push_str(&format!("{byte:02x} "));
        }
        // Pad remaining
        for j in chunk.len()..16 {
            if j == 8 {
                out.push(' ');
            }
            out.push_str("   ");
        }

        out.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_hex_dump() {
        let data = b"Hello, World!";
        let dump = hex_dump(data, 0);
        assert!(dump.contains("48 65 6c 6c 6f"));
        assert!(dump.contains("|Hello, World!"));
    }

    #[test]
    fn test_dissection_tree_display() {
        let mut tree = DissectionTree::new();
        tree.push_layer(ProtocolNode {
            protocol: "Ethernet".into(),
            byte_range: 0..14,
            fields: vec![Field {
                name: "Dst MAC".into(),
                display_value: "ff:ff:ff:ff:ff:ff".into(),
                byte_range: 0..6,
                field_type: FieldType::MacAddress,
            }],
            summary: "Ethernet II".into(),
        });
        let text = tree.to_text();
        assert!(text.contains("Ethernet"));
        assert!(text.contains("Dst MAC"));
    }
}
