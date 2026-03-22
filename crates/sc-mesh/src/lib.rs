use sc_core::{Result, ShadowError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

/// Include tonic-generated code from the proto file.
pub mod proto {
    tonic::include_proto!("scrypt.mesh");
}

use proto::mesh_service_server::{MeshService, MeshServiceServer};
use proto::{
    AnalysisResult, HeartbeatRequest, HeartbeatResponse, JoinRequest, JoinResponse, PeerInfo,
    ResultRequest, TaskRequest, TaskResponse,
};

/// Tracked state for a connected peer.
#[derive(Debug, Clone)]
struct PeerState {
    info: PeerInfo,
    current_tasks: u64,
    last_heartbeat: std::time::Instant,
}

/// Tracked state for a submitted task.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum TaskState {
    Pending(proto::AnalysisTask),
    Complete(AnalysisResult),
}

/// Shared state across all gRPC handlers.
#[derive(Debug, Default)]
struct MeshState {
    peers: HashMap<String, PeerState>,
    tasks: HashMap<String, TaskState>,
}

/// The gRPC service implementation.
struct MeshServiceImpl {
    #[allow(dead_code)]
    node_id: String,
    state: Arc<RwLock<MeshState>>,
}

#[tonic::async_trait]
impl MeshService for MeshServiceImpl {
    async fn join_mesh(
        &self,
        request: Request<JoinRequest>,
    ) -> std::result::Result<Response<JoinResponse>, Status> {
        let req = request.into_inner();
        let peer = req
            .peer
            .ok_or_else(|| Status::invalid_argument("missing peer info"))?;

        let peer_id = peer.node_id.clone();
        info!(peer_id = %peer_id, addr = %peer.address, "Peer joining mesh");

        let mut state = self.state.write().await;
        let known: Vec<PeerInfo> = state.peers.values().map(|p| p.info.clone()).collect();

        state.peers.insert(
            peer_id.clone(),
            PeerState {
                info: peer,
                current_tasks: 0,
                last_heartbeat: std::time::Instant::now(),
            },
        );

        Ok(Response::new(JoinResponse {
            accepted: true,
            known_peers: known,
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> std::result::Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();
        let mut state = self.state.write().await;

        if let Some(peer) = state.peers.get_mut(&req.node_id) {
            peer.last_heartbeat = std::time::Instant::now();
            peer.current_tasks = req.current_tasks;
        } else {
            warn!(node_id = %req.node_id, "Heartbeat from unknown peer");
        }

        Ok(Response::new(HeartbeatResponse { acknowledged: true }))
    }

    async fn submit_task(
        &self,
        request: Request<TaskRequest>,
    ) -> std::result::Result<Response<TaskResponse>, Status> {
        let req = request.into_inner();
        let task = req
            .task
            .ok_or_else(|| Status::invalid_argument("missing task"))?;
        let task_id = task.task_id.clone();

        info!(task_id = %task_id, "Task submitted");

        let mut state = self.state.write().await;
        state
            .tasks
            .insert(task_id.clone(), TaskState::Pending(task));

        Ok(Response::new(TaskResponse {
            accepted: true,
            task_id,
        }))
    }

    async fn get_results(
        &self,
        request: Request<ResultRequest>,
    ) -> std::result::Result<Response<AnalysisResult>, Status> {
        let req = request.into_inner();
        let state = self.state.read().await;

        match state.tasks.get(&req.task_id) {
            Some(TaskState::Complete(result)) => Ok(Response::new(result.clone())),
            Some(TaskState::Pending(_)) => Err(Status::unavailable("task still pending")),
            None => Err(Status::not_found("task not found")),
        }
    }
}

/// Mesh node configuration and state.
pub struct MeshNode {
    node_id: String,
    listen_addr: String,
    peers: Vec<String>,
    state: Arc<RwLock<MeshState>>,
}

impl MeshNode {
    pub fn new(listen_addr: String, peers: Vec<String>) -> Self {
        let node_id = format!("node-{}", uuid_simple());
        Self {
            node_id,
            listen_addr,
            peers,
            state: Arc::new(RwLock::new(MeshState::default())),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Start the mesh node — binds gRPC server, connects to peers, runs heartbeat loop.
    pub async fn start(&self) -> Result<()> {
        let addr = self.listen_addr.parse().map_err(|e| ShadowError::Config {
            message: format!("Invalid listen address '{}': {e}", self.listen_addr),
        })?;

        info!(
            node_id = %self.node_id,
            addr = %self.listen_addr,
            peers = ?self.peers,
            "Starting mesh node"
        );

        let service = MeshServiceImpl {
            node_id: self.node_id.clone(),
            state: Arc::clone(&self.state),
        };

        // Spawn peer connection tasks
        let state = Arc::clone(&self.state);
        let node_id = self.node_id.clone();
        let peers = self.peers.clone();
        tokio::spawn(async move {
            for peer_addr in &peers {
                if let Err(e) = connect_to_peer(peer_addr, &node_id, &state).await {
                    warn!(peer = %peer_addr, error = %e, "Failed to connect to peer");
                }
            }
        });

        // Spawn heartbeat background task
        let state = Arc::clone(&self.state);
        let node_id = self.node_id.clone();
        tokio::spawn(async move {
            heartbeat_loop(&node_id, &state).await;
        });

        // Start the gRPC server
        Server::builder()
            .add_service(MeshServiceServer::new(service))
            .serve(addr)
            .await
            .map_err(|e| ShadowError::Network {
                message: format!("gRPC server error: {e}"),
            })?;

        Ok(())
    }
}

/// Connect to a known peer and exchange peer lists.
async fn connect_to_peer(addr: &str, node_id: &str, state: &Arc<RwLock<MeshState>>) -> Result<()> {
    use proto::mesh_service_client::MeshServiceClient;

    let endpoint = format!("http://{addr}");
    let mut client =
        MeshServiceClient::connect(endpoint)
            .await
            .map_err(|e| ShadowError::Network {
                message: format!("Cannot connect to peer {addr}: {e}"),
            })?;

    let cores = num_cpus() as u64;
    let response = client
        .join_mesh(JoinRequest {
            peer: Some(PeerInfo {
                node_id: node_id.to_string(),
                address: String::new(), // Remote doesn't need our listen addr in request
                available_cores: cores,
                memory_mb: 0,
            }),
        })
        .await
        .map_err(|e| ShadowError::Network {
            message: format!("JoinMesh RPC to {addr} failed: {e}"),
        })?;

    let join = response.into_inner();
    info!(
        peer = %addr,
        accepted = join.accepted,
        known_peers = join.known_peers.len(),
        "Connected to peer"
    );

    // Register discovered peers
    let mut state = state.write().await;
    for peer in join.known_peers {
        if !state.peers.contains_key(&peer.node_id) {
            state.peers.insert(
                peer.node_id.clone(),
                PeerState {
                    info: peer,
                    current_tasks: 0,
                    last_heartbeat: std::time::Instant::now(),
                },
            );
        }
    }

    Ok(())
}

/// Periodically evict stale peers (no heartbeat in 30 seconds).
async fn heartbeat_loop(_node_id: &str, state: &Arc<RwLock<MeshState>>) {
    let timeout = std::time::Duration::from_secs(30);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let mut st = state.write().await;
        let before = st.peers.len();
        st.peers.retain(|_, p| p.last_heartbeat.elapsed() < timeout);
        let evicted = before - st.peers.len();
        if evicted > 0 {
            info!(evicted, remaining = st.peers.len(), "Evicted stale peers");
        }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Generate a simple unique ID.
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}{:x}", duration.as_secs(), duration.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_node_creation() {
        let node = MeshNode::new("127.0.0.1:9000".into(), vec!["127.0.0.1:9001".into()]);
        assert!(node.node_id().starts_with("node-"));
    }

    #[test]
    fn test_uuid_simple() {
        let a = uuid_simple();
        let b = uuid_simple();
        // Not guaranteed different but should be non-empty
        assert!(!a.is_empty());
        assert!(!b.is_empty());
    }

    #[tokio::test]
    async fn test_mesh_state_default() {
        let state = MeshState::default();
        assert!(state.peers.is_empty());
        assert!(state.tasks.is_empty());
    }

    #[tokio::test]
    async fn test_join_mesh_rpc() {
        let state = Arc::new(RwLock::new(MeshState::default()));
        let service = MeshServiceImpl {
            node_id: "test-node".into(),
            state: Arc::clone(&state),
        };

        let request = Request::new(JoinRequest {
            peer: Some(PeerInfo {
                node_id: "peer-1".into(),
                address: "127.0.0.1:8001".into(),
                available_cores: 4,
                memory_mb: 1024,
            }),
        });

        let resp = service.join_mesh(request).await.unwrap();
        let join = resp.into_inner();
        assert!(join.accepted);
        assert!(join.known_peers.is_empty()); // First peer, no others known

        // Verify peer is registered
        let st = state.read().await;
        assert!(st.peers.contains_key("peer-1"));
    }

    #[tokio::test]
    async fn test_submit_and_get_task() {
        let state = Arc::new(RwLock::new(MeshState::default()));
        let service = MeshServiceImpl {
            node_id: "test-node".into(),
            state: Arc::clone(&state),
        };

        // Submit a task
        let task = proto::AnalysisTask {
            task_id: "task-1".into(),
            pcap_chunk: vec![],
            filter_expression: String::new(),
            max_depth: 5,
        };

        let resp = service
            .submit_task(Request::new(TaskRequest { task: Some(task) }))
            .await
            .unwrap();
        assert!(resp.into_inner().accepted);

        // Get results — should be pending
        let err = service
            .get_results(Request::new(ResultRequest {
                task_id: "task-1".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);

        // Simulate completion
        {
            let mut st = state.write().await;
            st.tasks.insert(
                "task-1".into(),
                TaskState::Complete(AnalysisResult {
                    task_id: "task-1".into(),
                    packet_count: 42,
                    stats_json: "{}".into(),
                    success: true,
                    error_message: String::new(),
                }),
            );
        }

        // Now fetch completed result
        let resp = service
            .get_results(Request::new(ResultRequest {
                task_id: "task-1".into(),
            }))
            .await
            .unwrap();
        let result = resp.into_inner();
        assert!(result.success);
        assert_eq!(result.packet_count, 42);
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let state = Arc::new(RwLock::new(MeshState::default()));
        let service = MeshServiceImpl {
            node_id: "test-node".into(),
            state: Arc::clone(&state),
        };

        // Join first
        service
            .join_mesh(Request::new(JoinRequest {
                peer: Some(PeerInfo {
                    node_id: "peer-1".into(),
                    address: "127.0.0.1:8001".into(),
                    available_cores: 4,
                    memory_mb: 1024,
                }),
            }))
            .await
            .unwrap();

        // Send heartbeat
        let resp = service
            .heartbeat(Request::new(HeartbeatRequest {
                node_id: "peer-1".into(),
                current_tasks: 3,
            }))
            .await
            .unwrap();
        assert!(resp.into_inner().acknowledged);

        // Check updated tasks
        let st = state.read().await;
        assert_eq!(st.peers["peer-1"].current_tasks, 3);
    }
}
