use sc_core::{OwnedPacket, Timestamp};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::debug;

/// Replay engine that replays packets with timing reconstruction.
pub struct ReplayEngine {
    /// Speed multiplier (1.0 = real-time, 2.0 = double speed, 0.0 = max speed)
    speed: f64,
}

impl ReplayEngine {
    pub fn new(speed: f64) -> Self {
        Self { speed }
    }

    /// Replay packets through a channel, respecting inter-packet timing.
    /// Returns a receiver that yields packets at the appropriate times.
    pub async fn replay(
        &self,
        packets: Vec<OwnedPacket>,
        buffer_size: usize,
    ) -> mpsc::Receiver<OwnedPacket> {
        let (tx, rx) = mpsc::channel(buffer_size);
        let speed = self.speed;

        tokio::spawn(async move {
            let mut last_ts: Option<Timestamp> = None;

            for packet in packets {
                // Calculate and apply inter-packet delay
                if speed > 0.0 {
                    if let Some(prev) = last_ts {
                        let delta = packet.timestamp.delta(&prev);
                        let adjusted = Duration::from_secs_f64(delta.as_secs_f64() / speed);
                        if adjusted.as_micros() > 100 {
                            sleep(adjusted).await;
                        }
                    }
                }

                last_ts = Some(packet.timestamp);

                if tx.send(packet).await.is_err() {
                    debug!("Replay receiver dropped, stopping");
                    break;
                }
            }
        });

        rx
    }
}
