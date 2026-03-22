use sc_pcap::AnalyzedPacket;
use sc_protocol::DissectionTree;

/// Format analyzed packets as an ASCII table.
pub fn format_table(packets: &[AnalyzedPacket], max: Option<usize>) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "{:<6} {:<18} {:<18} {:<18} {:<8} {:<6} {}\n",
        "No.", "Time", "Source", "Dest", "Proto", "Len", "Info"
    ));
    out.push_str(&"-".repeat(100));
    out.push('\n');

    let limit = max.unwrap_or(packets.len()).min(packets.len());

    for pkt in packets.iter().take(limit) {
        let tree = &pkt.tree;
        let (src, dst) = extract_addresses(tree);
        let info = tree.layers.last()
            .map(|l| l.summary.clone())
            .unwrap_or_default();

        out.push_str(&format!(
            "{:<6} {:<18} {:<18} {:<18} {:<8} {:<6} {}\n",
            pkt.index + 1,
            format!("{}", pkt.packet.timestamp),
            truncate(&src, 17),
            truncate(&dst, 17),
            tree.top_protocol,
            pkt.packet.data.len(),
            truncate(&info, 60),
        ));
    }

    if limit < packets.len() {
        out.push_str(&format!("\n... and {} more packets\n", packets.len() - limit));
    }

    out
}

/// Format analyzed packets as JSON.
pub fn format_json(packets: &[AnalyzedPacket], max: Option<usize>) -> String {
    let limit = max.unwrap_or(packets.len()).min(packets.len());

    let entries: Vec<serde_json::Value> = packets.iter().take(limit).map(|pkt| {
        serde_json::json!({
            "index": pkt.index + 1,
            "timestamp": format!("{}", pkt.packet.timestamp),
            "length": pkt.packet.data.len(),
            "protocol": pkt.tree.top_protocol,
            "layers": pkt.tree.layers.iter().map(|l| {
                serde_json::json!({
                    "protocol": l.protocol,
                    "summary": l.summary,
                    "fields": l.fields.iter().map(|f| {
                        serde_json::json!({
                            "name": f.name,
                            "value": f.display_value,
                        })
                    }).collect::<Vec<_>>()
                })
            }).collect::<Vec<_>>()
        })
    }).collect();

    serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".into())
}

/// Format analyzed packets as a hierarchical tree.
pub fn format_tree(packets: &[AnalyzedPacket], max: Option<usize>) -> String {
    let mut out = String::new();
    let limit = max.unwrap_or(packets.len()).min(packets.len());

    for pkt in packets.iter().take(limit) {
        out.push_str(&format!("═══ Packet #{} ═══ [{} bytes] ═══\n",
            pkt.index + 1, pkt.packet.data.len()));
        out.push_str(&pkt.tree.to_text());
        out.push('\n');
    }

    out
}

pub fn format_jsonl(packets: &[AnalyzedPacket], max: Option<usize>) -> String {
    let limit = max.unwrap_or(packets.len()).min(packets.len());
    let mut out = String::new();

    for pkt in packets.iter().take(limit) {
        let (src, dst) = extract_addresses(&pkt.tree);
        let entry = serde_json::json!({
            "index": pkt.index + 1,
            "timestamp": format!("{}", pkt.packet.timestamp),
            "length": pkt.packet.data.len(),
            "protocol": pkt.tree.top_protocol,
            "source": src,
            "destination": dst,
            "layers": pkt.tree.layers.iter().map(|l| {
                serde_json::json!({
                    "protocol": l.protocol,
                    "summary": l.summary,
                    "fields": l.fields.iter().map(|f| {
                        serde_json::json!({ "name": f.name, "value": f.display_value })
                    }).collect::<Vec<_>>()
                })
            }).collect::<Vec<_>>()
        });
        out.push_str(&serde_json::to_string(&entry).unwrap_or_default());
        out.push('\n');
    }

    out
}

pub fn format_csv(packets: &[AnalyzedPacket], max: Option<usize>) -> String {
    let limit = max.unwrap_or(packets.len()).min(packets.len());
    let mut out = String::from("No,Timestamp,Source,Destination,Protocol,Length,Info\n");

    for pkt in packets.iter().take(limit) {
        let tree = &pkt.tree;
        let (src, dst) = extract_addresses(tree);
        let info = tree.layers.last()
            .map(|l| l.summary.clone())
            .unwrap_or_default();

        let info_escaped = info.replace('"', "\"\"");
        out.push_str(&format!(
            "{},{},{},{},{},{},\"{}\"\n",
            pkt.index + 1,
            pkt.packet.timestamp,
            src,
            dst,
            tree.top_protocol,
            pkt.packet.data.len(),
            info_escaped,
        ));
    }

    out
}

fn extract_addresses(tree: &DissectionTree) -> (String, String) {
    for layer in &tree.layers {
        if layer.protocol == "IPv4" || layer.protocol == "IPv6" {
            let src = layer.fields.iter()
                .find(|f| f.name == "Source")
                .map(|f| f.display_value.clone())
                .unwrap_or_else(|| "?".into());
            let dst = layer.fields.iter()
                .find(|f| f.name == "Destination")
                .map(|f| f.display_value.clone())
                .unwrap_or_else(|| "?".into());
            return (src, dst);
        }
    }
    for layer in &tree.layers {
        if layer.protocol == "Ethernet" {
            let src = layer.fields.iter()
                .find(|f| f.name == "Source")
                .map(|f| f.display_value.clone())
                .unwrap_or_else(|| "?".into());
            let dst = layer.fields.iter()
                .find(|f| f.name == "Destination")
                .map(|f| f.display_value.clone())
                .unwrap_or_else(|| "?".into());
            return (src, dst);
        }
    }
    ("?".into(), "?".into())
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}
