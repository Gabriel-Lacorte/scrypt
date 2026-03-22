use pcap_parser::traits::PcapReaderIterator;
use sc_core::{OwnedPacket, ShadowError, Timestamp};
use std::path::Path;
use tracing::{debug, info};

/// Read packets from a PCAP or PCAPNG file.
pub struct PcapReader {
    packets: Vec<OwnedPacket>,
}

impl PcapReader {
    /// Open and read all packets from a PCAP/PCAPNG file.
    pub fn open(path: &Path) -> sc_core::Result<Self> {
        let data = std::fs::read(path).map_err(|e| ShadowError::Pcap {
            message: format!("failed to read PCAP file {}: {e}", path.display()),
        })?;

        info!(path = %path.display(), bytes = data.len(), "Reading PCAP file");

        let mut packets = Vec::new();

        // Try PCAP format first, then PCAPNG
        match Self::parse_pcap(&data) {
            Ok(pkts) => packets = pkts,
            Err(_) => {
                match Self::parse_pcapng(&data) {
                    Ok(pkts) => packets = pkts,
                    Err(e) => {
                        return Err(ShadowError::Pcap {
                            message: format!("failed to parse PCAP/PCAPNG: {e}"),
                        });
                    }
                }
            }
        }

        info!(count = packets.len(), "Loaded packets from PCAP");
        Ok(Self { packets })
    }

    fn parse_pcap(data: &[u8]) -> Result<Vec<OwnedPacket>, String> {
        use pcap_parser::*;

        let mut reader = LegacyPcapReader::new(65536, data)
            .map_err(|e| format!("not a valid PCAP: {e:?}"))?;

        let mut packets = Vec::new();

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::Legacy(packet) => {
                            let ts = Timestamp::new(
                                packet.ts_sec as u64,
                                packet.ts_usec,
                            );
                            packets.push(OwnedPacket {
                                timestamp: ts,
                                data: packet.data.to_vec(),
                                original_len: packet.origlen,
                                link_type: 1, // Ethernet
                            });
                        }
                        PcapBlockOwned::LegacyHeader(hdr) => {
                            debug!(magic = hdr.magic_number, "PCAP header");
                        }
                        _ => {}
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    // Need more data, but we've already read the whole file
                    reader.consume(0);
                    // Try to continue with refill
                    match reader.refill() {
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                Err(e) => return Err(format!("PCAP parse error: {e:?}")),
            }
        }

        Ok(packets)
    }

    fn parse_pcapng(data: &[u8]) -> Result<Vec<OwnedPacket>, String> {
        use pcap_parser::*;

        let mut reader = PcapNGReader::new(65536, data)
            .map_err(|e| format!("not a valid PCAPNG: {e:?}"))?;

        let mut packets = Vec::new();

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                            let ts_raw = ((epb.ts_high as u64) << 32) | (epb.ts_low as u64);
                            // Default resolution: microseconds
                            let secs = ts_raw / 1_000_000;
                            let micros = (ts_raw % 1_000_000) as u32;
                            packets.push(OwnedPacket {
                                timestamp: Timestamp::new(secs, micros),
                                data: epb.data.to_vec(),
                                original_len: epb.origlen,
                                link_type: 1,
                            });
                        }
                        _ => {}
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    reader.consume(0);
                    match reader.refill() {
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                Err(e) => return Err(format!("PCAPNG parse error: {e:?}")),
            }
        }

        Ok(packets)
    }

    /// Get all packets.
    pub fn packets(&self) -> &[OwnedPacket] {
        &self.packets
    }

    /// Get packet count.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}
