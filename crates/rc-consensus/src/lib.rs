use rc_types::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Maximum concurrent P2P connections
const MAX_CONNECTIONS: usize = 1000;

/// Peer node info
#[derive(Debug, Clone)]
pub struct Peer {
    pub id: Id,
    pub address: String,
    pub public_key: [u8; 32],
}

/// Messages between nodes
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ConsensusMessage {
    /// Leader proposes a new block
    Propose(Block),
    /// Follower signs the proposed block
    Sign(u64, NodeSignature), // (height, signature)
    /// Request pending transactions from peers
    RequestTxs,
    /// Submit transaction to leader
    SubmitTx(Transaction),
    /// View change: request leader rotation when current leader is unresponsive
    ViewChange {
        height: u64,
        round: u32,
        node_id: Id,
    },
    /// Peer discovery handshake
    Handshake {
        node_id: Id,
        public_key: [u8; 32],
        listen_addr: String,
    },
}

/// Compute blake3 hash of a block header (used as block identity and prev_hash)
pub fn block_header_hash(header: &BlockHeader) -> Hash {
    let bytes = bincode::serialize(header)
        .expect("BlockHeader serialization must not fail");
    rc_crypto::hash(&bytes)
}

/// Simple PBFT-like consensus for fixed validator set
/// Leader rotates each block: height % num_nodes
pub struct Consensus {
    node_id: Id,
    private_key: [u8; 32],
    peers: Vec<Peer>,
    min_signatures: usize,
    pending_txs: Vec<Transaction>,
    tx_sender: mpsc::Sender<Transaction>,
    tx_receiver: mpsc::Receiver<Transaction>,
    /// Current round for view change (0 = normal, >0 = view change rounds)
    round: u32,
    /// View change votes collected: (height, round) -> set of node_ids
    view_change_votes: std::collections::HashMap<(u64, u32), HashSet<Id>>,
}

impl Consensus {
    pub fn new(node_id: Id, private_key: [u8; 32], peers: Vec<Peer>, min_signatures: usize) -> Self {
        let (tx_sender, tx_receiver) = mpsc::channel(10000);
        Self {
            node_id,
            private_key,
            peers,
            min_signatures,
            pending_txs: Vec::new(),
            tx_sender,
            tx_receiver,
            round: 0,
            view_change_votes: std::collections::HashMap::new(),
        }
    }

    /// Get sender for submitting transactions
    pub fn tx_sender(&self) -> mpsc::Sender<Transaction> {
        self.tx_sender.clone()
    }

    /// Collect pending transactions from channel
    pub async fn collect_pending_txs(&mut self) {
        while let Ok(tx) = self.tx_receiver.try_recv() {
            self.pending_txs.push(tx);
        }
    }

    /// Check if there are pending transactions without consuming them
    pub fn has_pending_txs(&self) -> bool {
        !self.pending_txs.is_empty()
    }

    /// Drain and return pending transactions
    pub fn drain_pending_txs(&mut self) -> Vec<Transaction> {
        self.pending_txs.drain(..).collect()
    }

    /// Push external transactions (from RPC channel) into pending pool
    pub fn push_txs(&mut self, txs: Vec<Transaction>) {
        self.pending_txs.extend(txs);
    }

    /// Get the expected leader for a given height, accounting for view change round
    pub fn leader_for_height(&self, height: u64) -> Id {
        self.leader_for_height_round(height, self.round)
    }

    /// Get leader for a specific height and round
    pub fn leader_for_height_round(&self, height: u64, round: u32) -> Id {
        let all_nodes = self.all_node_ids();
        if all_nodes.is_empty() {
            return self.node_id;
        }
        let leader_index = ((height as usize) + (round as usize)) % all_nodes.len();
        all_nodes[leader_index]
    }

    /// Am I the leader for this height?
    pub fn is_leader(&self, height: u64) -> bool {
        self.leader_for_height(height) == self.node_id
    }

    /// Get current round
    pub fn round(&self) -> u32 {
        self.round
    }

    /// Initiate a view change: increment round when leader is unresponsive
    /// Returns true if view change threshold reached (majority of nodes voted)
    pub fn request_view_change(&mut self, height: u64) -> bool {
        let next_round = self.round + 1;
        let total_nodes = self.all_node_ids().len();
        let threshold = (total_nodes / 2) + 1; // simple majority

        let entry = self.view_change_votes
            .entry((height, next_round))
            .or_default();
        entry.insert(self.node_id);

        if entry.len() >= threshold {
            self.round = next_round;
            self.view_change_votes.retain(|&(h, _), _| h >= height);
            true
        } else {
            false
        }
    }

    /// Process a view change vote from another node
    /// Returns true if view change threshold reached
    pub fn receive_view_change(&mut self, height: u64, round: u32, from: &Id) -> bool {
        let total_nodes = self.all_node_ids().len();
        let threshold = (total_nodes / 2) + 1;

        let entry = self.view_change_votes
            .entry((height, round))
            .or_default();
        entry.insert(*from);

        if entry.len() >= threshold && round > self.round {
            self.round = round;
            self.view_change_votes.retain(|&(h, _), _| h >= height);
            true
        } else {
            false
        }
    }

    /// Reset round when a new block is finalized
    pub fn reset_round(&mut self) {
        self.round = 0;
        self.view_change_votes.clear();
    }

    /// Add a dynamically discovered peer (peer discovery)
    /// Returns true if the peer was new
    pub fn add_peer(&mut self, id: Id, public_key: [u8; 32], address: String) -> bool {
        // Don't add self
        if id == self.node_id {
            return false;
        }
        // Don't add duplicate
        if self.peers.iter().any(|p| p.id == id) {
            return false;
        }
        self.peers.push(Peer { id, address, public_key });
        true
    }

    /// Validate that a block's proposer is the correct leader for its height
    pub fn is_valid_proposer(&self, block: &Block) -> bool {
        block.header.proposer == self.leader_for_height(block.header.height)
    }

    /// Get the node's public key (= node_id)
    pub fn node_id(&self) -> Id {
        self.node_id
    }

    /// Get the node's private key
    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    /// Number of peers (excluding self)
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Create a block proposal (leader only)
    pub fn propose_block(&mut self, height: u64, prev_hash: Hash, state_root: Hash) -> Block {
        let transactions: Vec<Transaction> = self.pending_txs.drain(..).collect();
        let timestamp = now_ms();

        let tx_hash = compute_tx_hash(&transactions);

        let header = BlockHeader {
            height,
            prev_hash,
            timestamp,
            tx_count: transactions.len() as u32,
            tx_hash,
            state_root,
            proposer: self.node_id,
        };

        // Sign the block header
        let header_bytes = bincode::serialize(&header)
            .expect("BlockHeader serialization must not fail");
        let signature = rc_crypto::sign(&header_bytes, &self.private_key);

        Block {
            header,
            transactions,
            signatures: vec![NodeSignature {
                node_id: self.node_id,
                signature: rc_types::Signature(signature),
            }],
        }
    }

    /// Verify and sign a proposed block (follower)
    pub fn verify_and_sign(&self, block: &Block, expected_prev_hash: &Hash) -> Option<NodeSignature> {
        // Verify proposer is the correct leader for this height
        if !self.is_valid_proposer(block) {
            warn!(
                "Invalid proposer for height {}: got {}, expected {}",
                block.header.height,
                hex::encode(&block.header.proposer[..8]),
                hex::encode(&self.leader_for_height(block.header.height)[..8]),
            );
            return None;
        }

        // Verify previous hash
        if &block.header.prev_hash != expected_prev_hash {
            warn!("Block prev_hash mismatch at height {}", block.header.height);
            return None;
        }

        // Verify proposer's signature
        if let Some(proposer_sig) = block.signatures.first() {
            let header_bytes = bincode::serialize(&block.header)
                .expect("BlockHeader serialization must not fail");

            // Get proposer's public key (could be self or peer)
            let proposer_key = if proposer_sig.node_id == self.node_id {
                None // We don't verify our own signature
            } else {
                self.get_peer_key(&proposer_sig.node_id)
            };

            if let Some(key) = proposer_key {
                if !rc_crypto::verify(&header_bytes, &proposer_sig.signature.0, &key) {
                    warn!("Invalid proposer signature at height {}", block.header.height);
                    return None;
                }
            }
        } else {
            warn!("Block has no signatures at height {}", block.header.height);
            return None;
        }

        // Verify tx_hash matches transactions
        let computed_tx_hash = compute_tx_hash(&block.transactions);
        if computed_tx_hash != block.header.tx_hash {
            warn!("Block tx_hash mismatch at height {}", block.header.height);
            return None;
        }

        // Sign the block
        let header_bytes = bincode::serialize(&block.header)
            .expect("BlockHeader serialization must not fail");
        let signature = rc_crypto::sign(&header_bytes, &self.private_key);

        Some(NodeSignature {
            node_id: self.node_id,
            signature: rc_types::Signature(signature),
        })
    }

    /// Verify a node signature on a block header
    pub fn verify_block_signature(&self, block: &Block, sig: &NodeSignature) -> bool {
        // Get the signer's public key
        let pub_key = if sig.node_id == self.node_id {
            self.node_id // own key
        } else if let Some(key) = self.get_peer_key(&sig.node_id) {
            key
        } else {
            return false; // unknown signer
        };

        let header_bytes = bincode::serialize(&block.header)
            .expect("BlockHeader serialization must not fail");
        rc_crypto::verify(&header_bytes, &sig.signature.0, &pub_key)
    }

    /// Check if block has enough UNIQUE VALID signatures to finalize
    pub fn is_finalized(&self, block: &Block) -> bool {
        let mut unique_signers = HashSet::new();
        let header_bytes = bincode::serialize(&block.header)
            .expect("BlockHeader serialization must not fail");

        for sig in &block.signatures {
            // Skip duplicate signers
            if !unique_signers.insert(sig.node_id) {
                continue;
            }

            // Verify signature is valid
            let pub_key = if sig.node_id == self.node_id {
                self.node_id
            } else if let Some(key) = self.get_peer_key(&sig.node_id) {
                key
            } else {
                continue; // unknown signer
            };

            if !rc_crypto::verify(&header_bytes, &sig.signature.0, &pub_key) {
                unique_signers.remove(&sig.node_id); // invalid sig doesn't count
            }
        }

        unique_signers.len() >= self.min_signatures
    }

    /// Send message to a peer (with 5s timeout)
    pub async fn send_to_peer(&self, peer: &Peer, msg: &ConsensusMessage) -> Result<(), String> {
        let data = bincode::serialize(msg).map_err(|e| e.to_string())?;
        let len = (data.len() as u32).to_be_bytes();

        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&peer.address),
        )
        .await
        .map_err(|_| format!("Connect to {} timed out", peer.address))?
        .map_err(|e| format!("Connect to {} failed: {}", peer.address, e))?;

        stream.write_all(&len).await.map_err(|e| e.to_string())?;
        stream.write_all(&data).await.map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Broadcast message to all peers
    pub async fn broadcast(&self, msg: &ConsensusMessage) {
        for peer in &self.peers {
            if let Err(e) = self.send_to_peer(peer, msg).await {
                warn!("Failed to send to peer {}: {}", peer.address, e);
            }
        }
    }

    /// Start listening for incoming messages (with connection limiting)
    pub async fn listen(
        bind_address: &str,
        msg_sender: mpsc::Sender<(Id, ConsensusMessage)>,
    ) -> Result<(), String> {
        let listener = TcpListener::bind(bind_address)
            .await
            .map_err(|e| e.to_string())?;

        info!("Consensus listening on {}", bind_address);

        let active_connections = Arc::new(AtomicUsize::new(0));

        loop {
            let (mut stream, _addr) = listener.accept().await.map_err(|e| e.to_string())?;
            let sender = msg_sender.clone();
            let conn_count = active_connections.clone();

            // Reject if too many connections
            if conn_count.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                warn!("Connection limit reached, rejecting");
                continue;
            }
            conn_count.fetch_add(1, Ordering::Relaxed);

            tokio::spawn(async move {
                let _guard = ConnectionGuard(conn_count);

                // Read with timeout
                let result = tokio::time::timeout(Duration::from_secs(10), async {
                    // Read length prefix
                    let mut len_buf = [0u8; 4];
                    stream.read_exact(&mut len_buf).await?;
                    let len = u32::from_be_bytes(len_buf) as usize;

                    // Reject oversized messages (16MB limit)
                    if len > 16 * 1024 * 1024 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "oversized message",
                        ));
                    }

                    // Read message
                    let mut buf = vec![0u8; len];
                    stream.read_exact(&mut buf).await?;
                    Ok(buf)
                })
                .await;

                let buf = match result {
                    Ok(Ok(buf)) => buf,
                    _ => return, // timeout or read error
                };

                if let Ok(msg) = bincode::deserialize::<ConsensusMessage>(&buf) {
                    // Extract peer identity from the message itself
                    let peer_id = match &msg {
                        ConsensusMessage::Sign(_, sig) => sig.node_id,
                        ConsensusMessage::Propose(block) => block.header.proposer,
                        ConsensusMessage::SubmitTx(tx) => tx.sender,
                        ConsensusMessage::RequestTxs => [0u8; 32],
                        ConsensusMessage::ViewChange { node_id, .. } => *node_id,
                        ConsensusMessage::Handshake { node_id, .. } => *node_id,
                    };
                    let _ = sender.send((peer_id, msg)).await;
                }
            });
        }
    }

    // ── Helpers ──

    pub fn all_node_ids(&self) -> Vec<Id> {
        let mut ids: Vec<Id> = self.peers.iter().map(|p| p.id).collect();
        ids.push(self.node_id);
        ids.sort();
        ids
    }

    fn get_peer_key(&self, node_id: &Id) -> Option<[u8; 32]> {
        if node_id == &self.node_id {
            return None; // self
        }
        self.peers.iter().find(|p| &p.id == node_id).map(|p| p.public_key)
    }
}

/// RAII guard for tracking active connection count
struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Compute tx_hash from a list of transactions
pub fn compute_tx_hash(transactions: &[Transaction]) -> Hash {
    if transactions.is_empty() {
        EMPTY_HASH
    } else {
        let tx_bytes = bincode::serialize(transactions)
            .expect("Transaction serialization must not fail");
        rc_crypto::hash(&tx_bytes)
    }
}

/// Current unix timestamp in milliseconds
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(_seed: u8) -> (Id, [u8; 32]) {
        let (pub_key, priv_key) = rc_crypto::generate_keypair();
        (pub_key, priv_key)
    }

    fn make_consensus(node_id: Id, priv_key: [u8; 32], peers: Vec<Peer>, min_sigs: usize) -> Consensus {
        Consensus::new(node_id, priv_key, peers, min_sigs)
    }

    #[test]
    fn test_leader_rotation() {
        let (id1, pk1) = make_node(1);
        let (id2, _pk2) = make_node(2);
        let (id3, _pk3) = make_node(3);

        let peers = vec![
            Peer { id: id2, address: "127.0.0.1:1".to_string(), public_key: id2 },
            Peer { id: id3, address: "127.0.0.1:2".to_string(), public_key: id3 },
        ];

        let c = make_consensus(id1, pk1, peers, 2);

        let mut leaders = Vec::new();
        for h in 0..6 {
            leaders.push(c.is_leader(h));
        }
        // Pattern repeats every 3 blocks
        assert_eq!(leaders[0], leaders[3]);
        assert_eq!(leaders[1], leaders[4]);
        assert_eq!(leaders[2], leaders[5]);
    }

    #[test]
    fn test_solo_node_always_leader() {
        let (id, pk) = make_node(1);
        let c = make_consensus(id, pk, vec![], 1);

        for h in 0..10 {
            assert!(c.is_leader(h));
        }
    }

    #[test]
    fn test_propose_block() {
        let (id, pk) = make_node(1);
        let mut c = make_consensus(id, pk, vec![], 1);

        let block = c.propose_block(1, EMPTY_HASH, EMPTY_HASH);

        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.proposer, id);
        assert_eq!(block.header.tx_count, 0);
        assert_eq!(block.header.tx_hash, EMPTY_HASH);
        assert_eq!(block.signatures.len(), 1);
        assert_eq!(block.signatures[0].node_id, id);

        let header_bytes = bincode::serialize(&block.header).unwrap();
        assert!(rc_crypto::verify(&header_bytes, &block.signatures[0].signature.0, &id));
    }

    #[test]
    fn test_verify_and_sign_valid() {
        let (id1, pk1) = make_node(1);
        let (id2, pk2) = make_node(2);

        let peers_for_1 = vec![
            Peer { id: id2, address: "127.0.0.1:1".to_string(), public_key: id2 },
        ];
        let peers_for_2 = vec![
            Peer { id: id1, address: "127.0.0.1:2".to_string(), public_key: id1 },
        ];

        // Figure out who is leader for height 1 and have THAT node propose
        let c1_temp = make_consensus(id1, pk1, peers_for_1.clone(), 2);
        let leader = c1_temp.leader_for_height(1);

        let (mut proposer_c, verifier_c) = if leader == id1 {
            (
                make_consensus(id1, pk1, peers_for_1, 2),
                make_consensus(id2, pk2, peers_for_2, 2),
            )
        } else {
            (
                make_consensus(id2, pk2, peers_for_2, 2),
                make_consensus(id1, pk1, peers_for_1, 2),
            )
        };

        let block = proposer_c.propose_block(1, EMPTY_HASH, EMPTY_HASH);

        // Verifier signs
        let sig = verifier_c.verify_and_sign(&block, &EMPTY_HASH);
        assert!(sig.is_some());

        let sig = sig.unwrap();
        let header_bytes = bincode::serialize(&block.header).unwrap();
        assert!(rc_crypto::verify(&header_bytes, &sig.signature.0, &sig.node_id));
    }

    #[test]
    fn test_verify_and_sign_bad_prev_hash() {
        let (id1, pk1) = make_node(1);
        let (id2, pk2) = make_node(2);

        let peers_for_1 = vec![
            Peer { id: id2, address: "127.0.0.1:1".to_string(), public_key: id2 },
        ];
        let peers_for_2 = vec![
            Peer { id: id1, address: "127.0.0.1:2".to_string(), public_key: id1 },
        ];

        let c1_temp = make_consensus(id1, pk1, peers_for_1.clone(), 2);
        let leader = c1_temp.leader_for_height(1);

        let (mut proposer_c, verifier_c) = if leader == id1 {
            (
                make_consensus(id1, pk1, peers_for_1, 2),
                make_consensus(id2, pk2, peers_for_2, 2),
            )
        } else {
            (
                make_consensus(id2, pk2, peers_for_2, 2),
                make_consensus(id1, pk1, peers_for_1, 2),
            )
        };

        let block = proposer_c.propose_block(1, EMPTY_HASH, EMPTY_HASH);

        let wrong_prev = [1u8; 32];
        let sig = verifier_c.verify_and_sign(&block, &wrong_prev);
        assert!(sig.is_none());
    }

    #[test]
    fn test_verify_rejects_wrong_proposer() {
        let (id1, pk1) = make_node(1);
        let (id2, pk2) = make_node(2);

        let peers_for_1 = vec![
            Peer { id: id2, address: "127.0.0.1:1".to_string(), public_key: id2 },
        ];
        let peers_for_2 = vec![
            Peer { id: id1, address: "127.0.0.1:2".to_string(), public_key: id1 },
        ];

        let c1_temp = make_consensus(id1, pk1, peers_for_1.clone(), 2);
        let leader = c1_temp.leader_for_height(1);

        // Have the NON-leader propose (should be rejected)
        let (mut wrong_proposer, verifier) = if leader == id1 {
            (
                make_consensus(id2, pk2, peers_for_2, 2),
                make_consensus(id1, pk1, peers_for_1, 2),
            )
        } else {
            (
                make_consensus(id1, pk1, peers_for_1, 2),
                make_consensus(id2, pk2, peers_for_2, 2),
            )
        };

        let block = wrong_proposer.propose_block(1, EMPTY_HASH, EMPTY_HASH);
        let sig = verifier.verify_and_sign(&block, &EMPTY_HASH);
        assert!(sig.is_none()); // Rejected: wrong proposer
    }

    #[test]
    fn test_finalization_threshold_unique_sigs() {
        let (id1, pk1) = make_node(1);
        let (id2, pk2) = make_node(2);
        let (id3, pk3) = make_node(3);

        let all_peers_for = |me: Id, me_pk: [u8; 32], others: Vec<(Id, [u8; 32])>| {
            let peers: Vec<Peer> = others.iter().map(|(id, _)| {
                Peer { id: *id, address: "x".to_string(), public_key: *id }
            }).collect();
            make_consensus(me, me_pk, peers, 3)
        };

        let mut c1 = all_peers_for(id1, pk1, vec![(id2, pk2), (id3, pk3)]);
        let c2 = all_peers_for(id2, pk2, vec![(id1, pk1), (id3, pk3)]);
        let c3 = all_peers_for(id3, pk3, vec![(id1, pk1), (id2, pk2)]);

        // Find height where id1 is leader
        let mut h = 0;
        while !c1.is_leader(h) { h += 1; }

        let mut block = c1.propose_block(h, EMPTY_HASH, EMPTY_HASH);
        assert!(!c1.is_finalized(&block)); // 1 sig

        // Add sig from node2
        block.signatures.push(c2.verify_and_sign(&block, &EMPTY_HASH).unwrap());
        assert!(!c1.is_finalized(&block)); // 2 unique sigs

        // Add DUPLICATE sig from node2 (should not count)
        block.signatures.push(c2.verify_and_sign(&block, &EMPTY_HASH).unwrap());
        assert!(!c1.is_finalized(&block)); // still 2 unique sigs

        // Add sig from node3
        block.signatures.push(c3.verify_and_sign(&block, &EMPTY_HASH).unwrap());
        assert!(c1.is_finalized(&block)); // 3 unique sigs = finalized
    }

    #[test]
    fn test_finalization_rejects_invalid_sig() {
        let (id1, pk1) = make_node(1);
        let (id2, _pk2) = make_node(2);

        let peers = vec![
            Peer { id: id2, address: "x".to_string(), public_key: id2 },
        ];

        let mut c1 = make_consensus(id1, pk1, peers, 2);

        let mut h = 0;
        while !c1.is_leader(h) { h += 1; }

        let mut block = c1.propose_block(h, EMPTY_HASH, EMPTY_HASH);

        // Add a forged signature (wrong bytes)
        block.signatures.push(NodeSignature {
            node_id: id2,
            signature: Signature([0xFFu8; 64]),
        });
        assert!(!c1.is_finalized(&block)); // forged sig doesn't count
    }

    #[test]
    fn test_block_header_hash_deterministic() {
        let header = BlockHeader {
            height: 1,
            prev_hash: EMPTY_HASH,
            timestamp: 12345,
            tx_count: 0,
            tx_hash: EMPTY_HASH,
            state_root: EMPTY_HASH,
            proposer: [1u8; 32],
        };

        let h1 = block_header_hash(&header);
        let h2 = block_header_hash(&header);
        assert_eq!(h1, h2);

        let header2 = BlockHeader {
            height: 2,
            ..header.clone()
        };
        let h3 = block_header_hash(&header2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_view_change_rotates_leader() {
        let (id1, pk1) = make_node(1);
        let (id2, _pk2) = make_node(2);
        let (id3, _pk3) = make_node(3);

        let peers = vec![
            Peer { id: id2, address: "x".to_string(), public_key: id2 },
            Peer { id: id3, address: "x".to_string(), public_key: id3 },
        ];

        let mut c1 = make_consensus(id1, pk1, peers, 2);

        let leader_r0 = c1.leader_for_height(1);

        // Single node votes for view change — not enough
        assert!(!c1.request_view_change(1));

        // Receive vote from another node — now 2/3 = majority
        let other = if id2 != id1 { id2 } else { id3 };
        let changed = c1.receive_view_change(1, 1, &other);
        assert!(changed);
        assert_eq!(c1.round(), 1);

        // Leader should be different after view change
        let leader_r1 = c1.leader_for_height(1);
        assert_ne!(leader_r0, leader_r1);

        // Reset round on block finalization
        c1.reset_round();
        assert_eq!(c1.round(), 0);
        assert_eq!(c1.leader_for_height(1), leader_r0);
    }

    #[test]
    fn test_peer_discovery() {
        let (id1, pk1) = make_node(1);
        let (id2, _pk2) = make_node(2);
        let (id3, _pk3) = make_node(3);

        let mut c = make_consensus(id1, pk1, vec![], 1);
        assert_eq!(c.peer_count(), 0);

        // Add new peer
        assert!(c.add_peer(id2, id2, "127.0.0.1:1000".to_string()));
        assert_eq!(c.peer_count(), 1);

        // Duplicate rejected
        assert!(!c.add_peer(id2, id2, "127.0.0.1:1000".to_string()));
        assert_eq!(c.peer_count(), 1);

        // Self rejected
        assert!(!c.add_peer(id1, id1, "127.0.0.1:2000".to_string()));
        assert_eq!(c.peer_count(), 1);

        // Third peer added
        assert!(c.add_peer(id3, id3, "127.0.0.1:3000".to_string()));
        assert_eq!(c.peer_count(), 2);
    }

    #[test]
    fn test_compute_tx_hash() {
        let hash_empty = compute_tx_hash(&[]);
        assert_eq!(hash_empty, EMPTY_HASH);

        let tx = Transaction {
            payload: TxPayload::DeactivateParticipant { id: [1u8; 32] },
            sender: [2u8; 32],
            signature: Signature::default(),
            timestamp: 1000,
            nonce: 1,
        };

        let h1 = compute_tx_hash(&[tx.clone()]);
        let h2 = compute_tx_hash(&[tx]);
        assert_eq!(h1, h2);
        assert_ne!(h1, EMPTY_HASH);
    }
}
