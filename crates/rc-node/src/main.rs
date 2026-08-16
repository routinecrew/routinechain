use clap::{Parser, Subcommand};
use rc_consensus::{block_header_hash, Consensus, ConsensusMessage, Peer};
use rc_state::StateMachine;
use rc_store::Store;
use rc_types::*;
use std::fs;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "rcw")]
#[command(about = "RoutineChain -- Commerce Trust Protocol")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the node
    Start {
        /// Path to config file
        #[arg(short, long, default_value = "config.yml")]
        config: String,
    },
    /// Generate a new keypair
    Keygen {
        /// Output path for the key file
        #[arg(short, long, default_value = "validator.key")]
        output: String,
    },
    /// Show chain status
    Status {
        /// RPC endpoint
        #[arg(short, long, default_value = "http://localhost:26657")]
        rpc: String,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => start_node(&config).await,
        Commands::Keygen { output } => keygen(&output),
        Commands::Status { rpc } => status(&rpc).await,
    }
}

async fn start_node(config_path: &str) {
    info!("Starting routinechain node...");

    // Load config
    let config: NodeConfig = match fs::read_to_string(config_path) {
        Ok(config_str) => {
            serde_yaml::from_str(&config_str)
                .or_else(|_| serde_json::from_str(&config_str))
                .unwrap_or_else(|e| {
                    warn!("Failed to parse config: {}, using defaults", e);
                    NodeConfig::default()
                })
        }
        Err(_) => {
            info!("Config not found at {}, using defaults", config_path);
            NodeConfig::default()
        }
    };

    // Open store (Clone shares Arc<DB>)
    let store = Store::open(&config.node.data_path)
        .expect("Failed to open database");

    let latest_height = store.get_latest_height();
    info!("Database opened. Latest height: {}", latest_height);

    // Load or generate validator keypair
    let (node_public_key, node_private_key) = load_or_generate_keypair(&config.node.private_key_path);
    info!("Node ID: {}", hex::encode(node_public_key));

    // Initialize genesis if needed
    if store.get_block(0).unwrap_or(None).is_none() {
        info!("Creating genesis block...");
        let genesis = Block::genesis(rc_consensus::now_ms(), node_public_key);
        store.put_block(&genesis).expect("Failed to store genesis");
        info!("Genesis block created");
    }

    // Build peer list
    let peers: Vec<Peer> = config.peers.iter().filter_map(|p| {
        let id_bytes = hex::decode(&p.id).ok()?;
        let pk_bytes = hex::decode(&p.public_key).ok()?;
        if id_bytes.len() != 32 || pk_bytes.len() != 32 {
            warn!("Invalid peer config: {}", p.id);
            return None;
        }
        let mut id = [0u8; 32];
        let mut pk = [0u8; 32];
        id.copy_from_slice(&id_bytes);
        pk.copy_from_slice(&pk_bytes);
        Some(Peer { id, address: p.address.clone(), public_key: pk })
    }).collect();

    let peer_count = peers.len();
    let min_signatures = if peer_count == 0 { 1 } else { config.consensus.min_signatures };

    // Initialize consensus
    let consensus = Arc::new(Mutex::new(
        Consensus::new(node_public_key, node_private_key, peers, min_signatures),
    ));

    // Create RPC transaction channel
    let (rpc_tx_sender, mut rpc_tx_receiver) = mpsc::channel::<Transaction>(10000);

    // Create consensus message channel for P2P
    let (_msg_sender, mut msg_receiver) = mpsc::channel::<(Id, ConsensusMessage)>(1000);

    // Parse platform keys for anchor authorization
    let platform_keys: Vec<Id> = config.platform_keys.iter().filter_map(|hex_str| {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 { return None; }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Some(id)
    }).collect();
    if !platform_keys.is_empty() {
        info!("Loaded {} platform key(s) for anchor authorization", platform_keys.len());
    }

    // Create state machine
    let state_machine = Arc::new(Mutex::new(
        StateMachine::new(store.clone(), config.rcw.rewards.clone())
            .with_dispute_threshold(config.dispute.vote_threshold)
            .with_platform_keys(platform_keys),
    ));

    // Start RPC server
    let rpc_store = store.clone();
    let rpc_address = config.rpc.address.clone();
    tokio::spawn(async move {
        let router = rc_rpc::create_router(rpc_store, rpc_tx_sender).await;
        let listener = tokio::net::TcpListener::bind(&rpc_address)
            .await
            .expect("Failed to bind RPC");
        info!("RPC server listening on {}", rpc_address);
        axum::serve(listener, router).await.unwrap();
    });

    // Start P2P consensus listener
    if peer_count > 0 {
        let listen_addr = config.consensus.listen_address.clone();
        let p2p_msg_sender = _msg_sender.clone();
        tokio::spawn(async move {
            if let Err(e) = Consensus::listen(&listen_addr, p2p_msg_sender).await {
                error!("Consensus listen error: {}", e);
            }
        });
    }

    info!("routinechain node started successfully");
    info!("  Chain: routinechain v{}", env!("CARGO_PKG_VERSION"));
    info!("  RPC: http://{}", config.rpc.address);
    info!("  Peers: {}", peer_count);
    info!("  Data: {}", config.node.data_path);
    info!("  Block time: {}ms", config.consensus.block_time_ms);

    // Perform peer discovery handshake on startup
    if peer_count > 0 {
        let cons = consensus.lock().await;
        let listen_addr = config.consensus.listen_address.clone();
        let handshake = ConsensusMessage::Handshake {
            node_id: node_public_key,
            public_key: node_public_key,
            listen_addr,
        };
        cons.broadcast(&handshake).await;
        info!("Peer discovery handshake sent to {} peers", peer_count);
    }

    // ── Block Production Loop ──
    let block_time = std::time::Duration::from_millis(config.consensus.block_time_ms);
    let mut interval = tokio::time::interval(block_time);
    let signature_wait_ms = config.consensus.block_time_ms / 2;
    let view_change_timeout_ms = config.consensus.view_change_timeout_ms;

    // Pending block awaiting signatures (multi-node only)
    let mut pending_block: Option<Block> = None;
    // Track when we last saw a new block (for view change timeout)
    let mut last_block_time_ms = rc_consensus::now_ms();

    loop {
        interval.tick().await;

        // 1. Drain RPC transactions
        let mut incoming_txs = Vec::new();
        while let Ok(tx) = rpc_tx_receiver.try_recv() {
            incoming_txs.push(tx);
        }

        // 2. Drain P2P messages
        let mut proposals = Vec::new();
        while let Ok((_peer_id, msg)) = msg_receiver.try_recv() {
            match msg {
                ConsensusMessage::SubmitTx(tx) => incoming_txs.push(tx),
                ConsensusMessage::Propose(block) => proposals.push(block),
                ConsensusMessage::Sign(height, sig) => {
                    // Collect signatures for pending block
                    if let Some(ref mut pb) = pending_block {
                        if pb.header.height == height {
                            let cons = consensus.lock().await;
                            if cons.verify_block_signature(pb, &sig) {
                                pb.signatures.push(sig);
                            } else {
                                warn!("Invalid signature for height {} from {}",
                                    height, hex::encode(&sig.node_id[..8]));
                            }
                        }
                    }
                }
                ConsensusMessage::RequestTxs => {}
                ConsensusMessage::ViewChange { height, round, node_id: from } => {
                    let mut cons = consensus.lock().await;
                    if cons.receive_view_change(height, round, &from) {
                        info!("View change completed for height {} round {}", height, round);
                    }
                }
                ConsensusMessage::Handshake { node_id: peer_id, public_key, listen_addr } => {
                    let mut cons = consensus.lock().await;
                    if cons.add_peer(peer_id, public_key, listen_addr.clone()) {
                        info!("Discovered new peer: {} at {}", hex::encode(&peer_id[..8]), listen_addr);
                        // Send handshake back so the new peer knows about us
                        let reply = ConsensusMessage::Handshake {
                            node_id: node_public_key,
                            public_key: node_public_key,
                            listen_addr: config.consensus.listen_address.clone(),
                        };
                        let new_peer = Peer { id: peer_id, address: listen_addr, public_key };
                        let _ = cons.send_to_peer(&new_peer, &reply).await;
                    }
                }
            }
        }

        // 3. Finalize pending block if enough signatures arrived
        if let Some(ref pb) = pending_block {
            let mut cons = consensus.lock().await;
            if cons.is_finalized(pb) {
                let sm = state_machine.lock().await;
                match sm.store().put_block(pb) {
                    Ok(()) => {
                        info!("Block {} finalized with {} signatures",
                            pb.header.height, pb.signature_count());
                        last_block_time_ms = rc_consensus::now_ms();
                        cons.reset_round();
                    }
                    Err(e) => error!("Failed to store finalized block: {}", e),
                }
                drop(cons);
                drop(sm);
                pending_block = None;
            } else {
                // Check timeout: if block is too old, discard
                let age_ms = rc_consensus::now_ms() - pb.header.timestamp;
                if age_ms > (signature_wait_ms * 4) as i64 {
                    warn!("Block {} timed out waiting for signatures, discarding", pb.header.height);
                    pending_block = None;
                }
            }
        }

        // 4. Handle incoming proposals (follower mode)
        for proposal in proposals {
            handle_proposal(&consensus, &state_machine, &store, proposal).await;
        }

        // 5. Feed transactions to consensus
        {
            let mut cons = consensus.lock().await;
            cons.push_txs(incoming_txs);
            cons.collect_pending_txs().await;
        }

        // 6. Don't produce new block if one is pending finalization
        if pending_block.is_some() {
            continue;
        }

        // 6.5. View change timeout: if no new block for too long, trigger view change
        if peer_count > 0 {
            let elapsed = rc_consensus::now_ms() - last_block_time_ms;
            if elapsed > view_change_timeout_ms as i64 {
                let height = store.get_latest_height() + 1;
                let mut cons = consensus.lock().await;
                let round = cons.round() + 1;
                if cons.request_view_change(height) {
                    info!("View change triggered for height {} round {}", height, round);
                    last_block_time_ms = rc_consensus::now_ms(); // reset timer
                }
                // Broadcast view change to peers
                cons.broadcast(&ConsensusMessage::ViewChange {
                    height,
                    round,
                    node_id: node_public_key,
                }).await;
            }
        }

        // 7. Check if we should produce a block
        let height = store.get_latest_height() + 1;

        let (is_leader, has_txs) = {
            let cons = consensus.lock().await;
            (cons.is_leader(height), cons.has_pending_txs())
        };

        if !is_leader || !has_txs {
            continue;
        }

        // 8. Leader: build and propose block
        let prev_hash = match store.get_block(height - 1) {
            Ok(Some(prev)) => block_header_hash(&prev.header),
            _ => {
                error!("Cannot find previous block at height {}", height - 1);
                continue;
            }
        };

        let mut cons = consensus.lock().await;
        let txs_to_execute = cons.drain_pending_txs();
        let tx_count = txs_to_execute.len();

        // Execute transactions against state
        let mut sm = state_machine.lock().await;
        let timestamp = rc_consensus::now_ms();
        let mut all_events = Vec::new();
        let mut valid_txs = Vec::new();

        for tx in txs_to_execute {
            match sm.execute(&tx, timestamp) {
                Ok(events) => {
                    all_events.extend(events);
                    valid_txs.push(tx);
                }
                Err(e) => {
                    warn!("Transaction rejected: {}", e);
                }
            }
        }

        if valid_txs.is_empty() {
            continue;
        }

        // Compute state root after execution
        let state_root = sm.store().compute_state_root();

        // Build block
        let tx_hash = rc_consensus::compute_tx_hash(&valid_txs);
        let header = BlockHeader {
            height,
            prev_hash,
            timestamp,
            tx_count: valid_txs.len() as u32,
            tx_hash,
            state_root,
            proposer: cons.node_id(),
        };

        let header_bytes = bincode::serialize(&header)
            .expect("BlockHeader serialization must not fail");
        let signature = rc_crypto::sign(&header_bytes, cons.private_key());

        let block = Block {
            header,
            transactions: valid_txs,
            signatures: vec![NodeSignature {
                node_id: cons.node_id(),
                signature: Signature(signature),
            }],
        };

        if cons.peer_count() > 0 {
            // Multi-node: broadcast and wait for signatures
            cons.broadcast(&ConsensusMessage::Propose(block.clone())).await;
            drop(cons);
            drop(sm);

            // If already finalized (min_signatures=1), store immediately
            let mut cons = consensus.lock().await;
            if cons.is_finalized(&block) {
                let sm = state_machine.lock().await;
                sm.store().put_block(&block)
                    .map_err(|e| error!("Failed to store block: {}", e)).ok();
                last_block_time_ms = rc_consensus::now_ms();
                cons.reset_round();
                info!(
                    "Block {} produced: {} txs ({} submitted), {} events",
                    height, block.header.tx_count, tx_count, all_events.len(),
                );
            } else {
                // Wait for signatures in subsequent loop iterations
                pending_block = Some(block);
                info!("Block {} proposed, awaiting signatures...", height);
            }
        } else {
            // Solo node: immediately final
            sm.store().put_block(&block)
                .map_err(|e| error!("Failed to store block: {}", e)).ok();
            last_block_time_ms = rc_consensus::now_ms();

            info!(
                "Block {} produced: {} txs ({} submitted), {} events, state_root={}",
                height,
                block.header.tx_count,
                tx_count,
                all_events.len(),
                hex::encode(&block.header.state_root[..8]),
            );
        }
    }
}

/// Handle an incoming block proposal (follower)
async fn handle_proposal(
    consensus: &Arc<Mutex<Consensus>>,
    state_machine: &Arc<Mutex<StateMachine>>,
    store: &Store,
    block: Block,
) {
    let height = block.header.height;
    if block.is_genesis() {
        return;
    }

    // Fork detection: reject block if we already have one at this height
    if let Ok(Some(_)) = store.get_block(height) {
        warn!("Fork detected: already have block at height {}, rejecting proposal", height);
        return;
    }

    let prev_hash = match store.get_block(height - 1) {
        Ok(Some(prev)) => block_header_hash(&prev.header),
        _ => {
            warn!("Cannot verify proposal: missing block {}", height - 1);
            return;
        }
    };

    let cons = consensus.lock().await;

    // Proposer validation is done inside verify_and_sign (is_valid_proposer check)
    let node_sig = cons.verify_and_sign(&block, &prev_hash);

    if let Some(sig) = node_sig {
        // Send signature back to proposer
        cons.broadcast(&ConsensusMessage::Sign(height, sig)).await;
        drop(cons);

        // Apply block locally
        let mut sm = state_machine.lock().await;
        match sm.apply_block(&block) {
            Ok(events) => {
                info!("Applied proposal block {}: {} txs, {} events",
                    height, block.header.tx_count, events.len());
            }
            Err(e) => {
                error!("Failed to apply proposal block {}: {}", height, e);
            }
        }
    } else {
        warn!("Rejected proposal at height {}", height);
    }
}

fn load_or_generate_keypair(path: &str) -> ([u8; 32], [u8; 32]) {
    if let Ok(contents) = fs::read_to_string(path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
            let pub_hex = json["public_key"].as_str().unwrap_or_default();
            let priv_hex = json["private_key"].as_str().unwrap_or_default();
            if let (Ok(pub_bytes), Ok(priv_bytes)) = (hex::decode(pub_hex), hex::decode(priv_hex)) {
                if pub_bytes.len() == 32 && priv_bytes.len() == 32 {
                    let mut pub_key = [0u8; 32];
                    let mut priv_key = [0u8; 32];
                    pub_key.copy_from_slice(&pub_bytes);
                    priv_key.copy_from_slice(&priv_bytes);
                    info!("Loaded keypair from {}", path);
                    return (pub_key, priv_key);
                }
            }
        }
    }
    info!("No keypair found at {}, generating new one", path);
    let (pub_key, priv_key) = rc_crypto::generate_keypair();
    let key_data = serde_json::json!({
        "public_key": hex::encode(pub_key),
        "private_key": hex::encode(priv_key),
    });
    if let Err(e) = fs::write(path, serde_json::to_string_pretty(&key_data).unwrap()) {
        warn!("Could not save keypair to {}: {}", path, e);
    }
    (pub_key, priv_key)
}

fn keygen(output: &str) {
    let (public_key, private_key) = rc_crypto::generate_keypair();

    let key_data = serde_json::json!({
        "public_key": hex::encode(public_key),
        "private_key": hex::encode(private_key),
    });

    fs::write(output, serde_json::to_string_pretty(&key_data).unwrap())
        .expect("Failed to write key file");

    println!("Keypair generated:");
    println!("  Public key:  {}", hex::encode(public_key));
    println!("  Private key: {}", hex::encode(private_key));
    println!("  Saved to:    {}", output);
}

async fn status(rpc: &str) {
    let url = format!("{}/status", rpc);
    match reqwest::get(&url).await {
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            println!("{}", body);
        }
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", rpc, e);
        }
    }
}
