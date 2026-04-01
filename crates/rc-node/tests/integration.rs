use rc_consensus::{block_header_hash, compute_tx_hash, Consensus, Peer};
use rc_state::StateMachine;
use rc_store::Store;
use rc_types::*;

fn setup_node(name: &str, pub_key: [u8; 32], priv_key: [u8; 32], peers: Vec<Peer>, min_sigs: usize) -> (Store, Consensus, StateMachine) {
    let path = format!("/tmp/rcw_integration_{}", name);
    let _ = std::fs::remove_dir_all(&path);
    let store = Store::open(&path).unwrap();
    let consensus = Consensus::new(pub_key, priv_key, peers, min_sigs);
    let reward_config = RewardConfig {
        settlement_recorded: 5,
        escrow_completed: 20,
        trust_90_monthly: 100,
        rating_submitted: 2,
        dispute_won: 50,
        referral: 50,
    };
    let sm = StateMachine::new(store.clone(), reward_config);
    (store, consensus, sm)
}

fn cleanup(names: &[&str]) {
    for name in names {
        let path = format!("/tmp/rcw_integration_{}", name);
        let _ = std::fs::remove_dir_all(&path);
    }
}

/// Full multi-node consensus integration test:
/// 1. Three nodes form a network
/// 2. Leader proposes blocks, followers verify and sign
/// 3. Blocks are finalized with enough signatures
/// 4. State is consistent across all nodes
#[test]
fn test_multi_node_consensus_e2e() {
    let (pub1, priv1) = rc_crypto::generate_keypair();
    let (pub2, priv2) = rc_crypto::generate_keypair();
    let (pub3, priv3) = rc_crypto::generate_keypair();

    let peers_for_1 = vec![
        Peer { id: pub2, address: "x".to_string(), public_key: pub2 },
        Peer { id: pub3, address: "x".to_string(), public_key: pub3 },
    ];
    let peers_for_2 = vec![
        Peer { id: pub1, address: "x".to_string(), public_key: pub1 },
        Peer { id: pub3, address: "x".to_string(), public_key: pub3 },
    ];
    let peers_for_3 = vec![
        Peer { id: pub1, address: "x".to_string(), public_key: pub1 },
        Peer { id: pub2, address: "x".to_string(), public_key: pub2 },
    ];

    let min_sigs = 2; // 2 out of 3
    let (store1, mut cons1, mut sm1) = setup_node("node1", pub1, priv1, peers_for_1, min_sigs);
    let (store2, mut cons2, mut sm2) = setup_node("node2", pub2, priv2, peers_for_2, min_sigs);
    let (store3, mut cons3, mut sm3) = setup_node("node3", pub3, priv3, peers_for_3, min_sigs);

    // Create genesis on all nodes
    let genesis = Block::genesis(1000, pub1);
    store1.put_block(&genesis).unwrap();
    store2.put_block(&genesis).unwrap();
    store3.put_block(&genesis).unwrap();

    // ── Block 1: Register a participant ──
    let height: u64 = 1;
    let prev_hash = block_header_hash(&genesis.header);

    // Determine leader for height 1
    let leader = cons1.leader_for_height(height);
    let (leader_pub, leader_priv, leader_sm, leader_store, leader_cons, follower_cons_list) =
        if leader == pub1 {
            (pub1, priv1, &mut sm1, &store1, &mut cons1, vec![&cons2, &cons3])
        } else if leader == pub2 {
            (pub2, priv2, &mut sm2, &store2, &mut cons2, vec![&cons1, &cons3])
        } else {
            (pub3, priv3, &mut sm3, &store3, &mut cons3, vec![&cons1, &cons2])
        };

    // Build transaction: sender == participant_id (self-registration with authorization)
    let payload = TxPayload::RegisterParticipant {
        id: leader_pub, // register self
        p_type: ParticipantType::Seller,
        metadata: "integration_test_seller".to_string(),
    };
    let payload_bytes = bincode::serialize(&payload).unwrap();
    let sig = rc_crypto::sign(&payload_bytes, &leader_priv);
    let tx = Transaction {
        payload,
        sender: leader_pub,
        signature: Signature(sig),
        timestamp: 2000,
        nonce: 1,
    };

    leader_cons.push_txs(vec![tx.clone()]);
    let txs = leader_cons.drain_pending_txs();

    // Execute transactions on leader
    let timestamp = 2000;
    let mut valid_txs = Vec::new();
    let mut all_events = Vec::new();
    for tx in txs {
        match leader_sm.execute(&tx, timestamp) {
            Ok(events) => {
                all_events.extend(events);
                valid_txs.push(tx);
            }
            Err(e) => panic!("TX execution failed: {}", e),
        }
    }
    assert_eq!(valid_txs.len(), 1);
    assert_eq!(all_events.len(), 1);

    // Compute state root
    let state_root = leader_sm.store().compute_state_root();

    // Build block
    let tx_hash = compute_tx_hash(&valid_txs);
    let header = BlockHeader {
        height,
        prev_hash,
        timestamp,
        tx_count: valid_txs.len() as u32,
        tx_hash,
        state_root,
        proposer: leader_pub,
    };

    let header_bytes = bincode::serialize(&header).unwrap();
    let signature = rc_crypto::sign(&header_bytes, &leader_priv);

    let mut block = Block {
        header,
        transactions: valid_txs,
        signatures: vec![NodeSignature {
            node_id: leader_pub,
            signature: Signature(signature),
        }],
    };

    // Not yet finalized (only 1 sig, need 2)
    assert!(!leader_cons.is_finalized(&block));

    // Followers verify and sign
    for fc in &follower_cons_list {
        let sig = fc.verify_and_sign(&block, &prev_hash);
        assert!(sig.is_some(), "Follower should accept valid proposal");
        block.signatures.push(sig.unwrap());
    }

    // Now finalized (3 sigs >= 2 min)
    assert!(leader_cons.is_finalized(&block));
    assert_eq!(block.signature_count(), 3);

    // Store block on leader
    leader_store.put_block(&block).unwrap();
    assert_eq!(leader_store.get_latest_height(), 1);

    // Apply block on followers (simulating block propagation)
    let follower_pairs: Vec<(&Store, &mut StateMachine)> = if leader == pub1 {
        vec![(&store2, &mut sm2), (&store3, &mut sm3)]
    } else if leader == pub2 {
        vec![(&store1, &mut sm1), (&store3, &mut sm3)]
    } else {
        vec![(&store1, &mut sm1), (&store2, &mut sm2)]
    };

    for (_fstore, fsm) in follower_pairs {
        let events = fsm.apply_block(&block).unwrap();
        assert_eq!(events.len(), 1);
    }

    // Verify state consistency: all nodes have the participant (registered as leader_pub)
    let p1 = store1.get_participant(&leader_pub).unwrap().unwrap();
    let p2 = store2.get_participant(&leader_pub).unwrap().unwrap();
    let p3 = store3.get_participant(&leader_pub).unwrap().unwrap();

    assert_eq!(p1.metadata, "integration_test_seller");
    assert_eq!(p2.metadata, "integration_test_seller");
    assert_eq!(p3.metadata, "integration_test_seller");

    // Verify state roots match across all nodes
    let root1 = store1.compute_state_root();
    let root2 = store2.compute_state_root();
    let root3 = store3.compute_state_root();
    assert_eq!(root1, root2);
    assert_eq!(root2, root3);

    // Verify block stored on all nodes
    assert_eq!(store1.get_latest_height(), 1);
    assert_eq!(store2.get_latest_height(), 1);
    assert_eq!(store3.get_latest_height(), 1);

    cleanup(&["node1", "node2", "node3"]);
}

/// Test that view change correctly rotates leader
#[test]
fn test_view_change_integration() {
    let (pub1, priv1) = rc_crypto::generate_keypair();
    let (pub2, _priv2) = rc_crypto::generate_keypair();
    let (pub3, _priv3) = rc_crypto::generate_keypair();

    let peers_for_1 = vec![
        Peer { id: pub2, address: "x".to_string(), public_key: pub2 },
        Peer { id: pub3, address: "x".to_string(), public_key: pub3 },
    ];

    let mut cons1 = Consensus::new(pub1, priv1, peers_for_1, 2);

    let height = 1;
    let original_leader = cons1.leader_for_height(height);

    // Simulate timeout: node1 requests view change
    cons1.request_view_change(height);

    // Receive vote from node2 (majority reached: 2 of 3)
    let changed = cons1.receive_view_change(height, 1, &pub2);
    assert!(changed);
    assert_eq!(cons1.round(), 1);

    // Leader should rotate
    let new_leader = cons1.leader_for_height(height);
    assert_ne!(original_leader, new_leader);

    // After block finalization, round resets
    cons1.reset_round();
    assert_eq!(cons1.round(), 0);
    assert_eq!(cons1.leader_for_height(height), original_leader);
}

/// Test peer discovery: new node joins dynamically
#[test]
fn test_peer_discovery_integration() {
    let (pub1, priv1) = rc_crypto::generate_keypair();
    let (pub2, _priv2) = rc_crypto::generate_keypair();
    let (pub3, _priv3) = rc_crypto::generate_keypair();

    let mut cons = Consensus::new(pub1, priv1, vec![], 1);
    assert_eq!(cons.peer_count(), 0);

    // Simulate receiving handshake from node2
    assert!(cons.add_peer(pub2, pub2, "10.0.0.2:26656".to_string()));
    assert_eq!(cons.peer_count(), 1);

    // Simulate receiving handshake from node3
    assert!(cons.add_peer(pub3, pub3, "10.0.0.3:26656".to_string()));
    assert_eq!(cons.peer_count(), 2);

    // Leader rotation now includes all 3 nodes
    let all = cons.all_node_ids();
    assert_eq!(all.len(), 3);

    // Duplicate handshake rejected
    assert!(!cons.add_peer(pub2, pub2, "10.0.0.2:26656".to_string()));
    assert_eq!(cons.peer_count(), 2);
}

/// Test nonce replay protection end-to-end (with authorization)
#[test]
fn test_nonce_replay_e2e() {
    let path = "/tmp/rcw_integration_nonce";
    let _ = std::fs::remove_dir_all(path);
    let store = Store::open(path).unwrap();
    let reward_config = RewardConfig {
        settlement_recorded: 5,
        escrow_completed: 20,
        trust_90_monthly: 100,
        rating_submitted: 2,
        dispute_won: 50,
        referral: 50,
    };
    let mut sm = StateMachine::new(store, reward_config);

    let sender = [10u8; 32];

    // nonce=1: register participant (sender == id for self-registration)
    let tx1 = Transaction {
        payload: TxPayload::RegisterParticipant {
            id: sender,
            p_type: ParticipantType::Seller,
            metadata: "s".to_string(),
        },
        sender,
        signature: Signature::default(),
        timestamp: 1000,
        nonce: 1,
    };
    sm.execute(&tx1, 1000).unwrap();

    // nonce=1 replay: rejected
    let tx_replay = Transaction {
        payload: TxPayload::UpdateParticipant {
            id: sender,
            metadata: "hacked".to_string(),
        },
        sender,
        signature: Signature::default(),
        timestamp: 1000,
        nonce: 1,
    };
    assert!(sm.execute(&tx_replay, 1000).is_err());

    // nonce=2: succeeds (sender == id for update)
    let tx2 = Transaction {
        payload: TxPayload::UpdateParticipant {
            id: sender,
            metadata: "updated".to_string(),
        },
        sender,
        signature: Signature::default(),
        timestamp: 2000,
        nonce: 2,
    };
    sm.execute(&tx2, 2000).unwrap();

    // Verify state reflects nonce=2 tx, not the replayed nonce=1
    let p = sm.store().get_participant(&sender).unwrap().unwrap();
    assert_eq!(p.metadata, "updated");

    let _ = std::fs::remove_dir_all(path);
}

/// Test authorization: unauthorized actions are rejected across the full flow
#[test]
fn test_authorization_e2e() {
    let path = "/tmp/rcw_integration_auth";
    let _ = std::fs::remove_dir_all(path);
    let store = Store::open(path).unwrap();
    let reward_config = RewardConfig {
        settlement_recorded: 5,
        escrow_completed: 20,
        trust_90_monthly: 100,
        rating_submitted: 2,
        dispute_won: 50,
        referral: 50,
    };
    let mut sm = StateMachine::new(store, reward_config);

    let alice = [1u8; 32];
    let bob = [2u8; 32];
    let eve = [3u8; 32]; // attacker

    use std::sync::atomic::{AtomicU64, Ordering};
    static NC: AtomicU64 = AtomicU64::new(100);
    let next_nonce = || NC.fetch_add(1, Ordering::Relaxed);

    // Register alice and bob
    sm.execute(&Transaction {
        payload: TxPayload::RegisterParticipant { id: alice, p_type: ParticipantType::Buyer, metadata: "alice".to_string() },
        sender: alice, signature: Signature::default(), timestamp: 1000, nonce: next_nonce(),
    }, 1000).unwrap();

    sm.execute(&Transaction {
        payload: TxPayload::RegisterParticipant { id: bob, p_type: ParticipantType::Seller, metadata: "bob".to_string() },
        sender: bob, signature: Signature::default(), timestamp: 1000, nonce: next_nonce(),
    }, 1000).unwrap();

    // Eve tries to update alice's profile -> rejected
    let err = sm.execute(&Transaction {
        payload: TxPayload::UpdateParticipant { id: alice, metadata: "hacked by eve".to_string() },
        sender: eve, signature: Signature::default(), timestamp: 1000, nonce: next_nonce(),
    }, 1000).unwrap_err();
    assert!(err.contains("Unauthorized"));

    // Eve tries to create escrow as if she were alice -> rejected
    let err = sm.execute(&Transaction {
        payload: TxPayload::CreateEscrow { escrow_id: [10u8; 32], buyer: alice, seller: bob, amount: 1000, expires_at: 99999 },
        sender: eve, signature: Signature::default(), timestamp: 1000, nonce: next_nonce(),
    }, 1000).unwrap_err();
    assert!(err.contains("Unauthorized"));

    // Alice creates escrow correctly
    sm.execute(&Transaction {
        payload: TxPayload::CreateEscrow { escrow_id: [10u8; 32], buyer: alice, seller: bob, amount: 1000, expires_at: 99999 },
        sender: alice, signature: Signature::default(), timestamp: 1000, nonce: next_nonce(),
    }, 1000).unwrap();

    // Bob tries to release (only buyer can) -> rejected
    let err = sm.execute(&Transaction {
        payload: TxPayload::ReleaseEscrow { escrow_id: [10u8; 32], evidence_hash: [0xABu8; 32] },
        sender: bob, signature: Signature::default(), timestamp: 2000, nonce: next_nonce(),
    }, 2000).unwrap_err();
    assert!(err.contains("Unauthorized"));

    // Alice's metadata unchanged (eve's attack failed)
    let p = sm.store().get_participant(&alice).unwrap().unwrap();
    assert_eq!(p.metadata, "alice");

    let _ = std::fs::remove_dir_all(path);
}
