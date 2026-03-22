use sc_core::{Result, ShadowError};
use tracing::info;

/// Mesh node configuration and state.
pub struct MeshNode {
    node_id: String,
    listen_addr: String,
    peers: Vec<String>,
}

impl MeshNode {
    pub fn new(listen_addr: String, peers: Vec<String>) -> Self {
        let node_id = format!("node-{}", uuid_simple());
        Self {
            node_id,
            listen_addr,
            peers,
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Start the mesh node (gRPC server).
    pub async fn start(&self) -> Result<()> {
        info!(
            node_id = %self.node_id,
            addr = %self.listen_addr,
            peers = ?self.peers,
            "Starting mesh node"
        );

        // Placeholder for tonic gRPC server initialization
        // Full implementation would:
        // 1. Start tonic server with MeshService impl
        // 2. Connect to known peers (JoinMesh RPC)
        // 3. Start heartbeat background task
        // 4. Accept incoming analysis tasks

        Ok(())
    }
}

/// Generate a simple unique ID (not a real UUID, but sufficient for node identification).
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}{:x}", duration.as_secs(), duration.subsec_nanos())
}
