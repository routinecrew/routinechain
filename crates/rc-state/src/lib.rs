pub mod modules;

use rc_store::Store;
use rc_types::*;
use tracing::{info, warn};

/// State machine -- executes transactions and updates state
pub struct StateMachine {
    store: Store,
    reward_config: RewardConfig,
    dispute_vote_threshold: usize,
    platform_keys: Vec<Id>,
}

impl StateMachine {
    pub fn new(store: Store, reward_config: RewardConfig) -> Self {
        Self {
            store,
            reward_config,
            dispute_vote_threshold: 3,
            platform_keys: Vec::new(),
        }
    }

    pub fn with_dispute_threshold(mut self, threshold: usize) -> Self {
        self.dispute_vote_threshold = threshold;
        self
    }

    pub fn with_platform_keys(mut self, keys: Vec<Id>) -> Self {
        self.platform_keys = keys;
        self
    }

    /// Verify a transaction's Ed25519 signature
    fn verify_tx_signature(tx: &Transaction) -> bool {
        let payload_bytes = match bincode::serialize(&tx.payload) {
            Ok(b) => b,
            Err(_) => return false,
        };
        rc_crypto::verify(&payload_bytes, &tx.signature.0, &tx.sender)
    }

    /// Validate and increment nonce for replay protection
    fn check_and_update_nonce(&self, tx: &Transaction) -> Result<(), String> {
        let current_nonce = self.store.get_nonce(&tx.sender);
        if tx.nonce <= current_nonce {
            return Err(format!(
                "Nonce too low: got {}, expected > {}",
                tx.nonce, current_nonce
            ));
        }
        self.store.set_nonce(&tx.sender, tx.nonce)?;
        Ok(())
    }

    /// Execute a single transaction, return events
    pub fn execute(&mut self, tx: &Transaction, timestamp: i64) -> Result<Vec<Event>, String> {
        // Validate nonce (replay protection)
        self.check_and_update_nonce(tx)?;

        match &tx.payload {
            // ── CTP: Participant ──
            TxPayload::RegisterParticipant {
                id,
                p_type,
                metadata,
            } => modules::participant::register(
                &self.store,
                &tx.sender,
                id,
                *p_type,
                metadata,
                timestamp,
            ),

            TxPayload::UpdateParticipant { id, metadata } => {
                modules::participant::update(&self.store, &tx.sender, id, metadata, timestamp)
            }

            TxPayload::DeactivateParticipant { id } => {
                modules::participant::deactivate(&self.store, &tx.sender, id)
            }

            // ── CTP: Settlement ──
            TxPayload::RecordSettlement {
                participant_id,
                record,
            } => modules::settlement::record(
                &self.store,
                &tx.sender,
                participant_id,
                record,
                timestamp,
                self.reward_config.settlement_recorded,
            ),

            TxPayload::RecordRating {
                participant_id,
                rating,
                success,
            } => modules::settlement::record_rating(
                &self.store,
                participant_id,
                *rating,
                *success,
                timestamp,
                self.reward_config.rating_submitted,
            ),

            // ── CTP: Escrow ──
            TxPayload::CreateEscrow {
                escrow_id,
                buyer,
                seller,
                amount,
                expires_at,
            } => modules::escrow::create(
                &self.store,
                &tx.sender,
                escrow_id,
                buyer,
                seller,
                *amount,
                *expires_at,
                timestamp,
            ),

            TxPayload::ReleaseEscrow {
                escrow_id,
                evidence_hash,
            } => modules::escrow::release(
                &self.store,
                &tx.sender,
                escrow_id,
                evidence_hash,
                timestamp,
                self.reward_config.escrow_completed,
            ),

            TxPayload::RefundEscrow { escrow_id } => {
                modules::escrow::refund(&self.store, &tx.sender, escrow_id, timestamp)
            }

            // ── CTP: Dispute ──
            TxPayload::RaiseDispute {
                dispute_id,
                escrow_id,
                reason,
                evidence_hash,
            } => modules::dispute::raise(
                &self.store,
                dispute_id,
                escrow_id,
                &tx.sender,
                *reason,
                evidence_hash,
                timestamp,
            ),

            TxPayload::SubmitEvidence {
                dispute_id,
                evidence_hash,
            } => modules::dispute::submit_evidence(
                &self.store,
                &tx.sender,
                dispute_id,
                evidence_hash,
            ),

            TxPayload::VoteDispute {
                dispute_id,
                decision,
            } => modules::dispute::vote(
                &self.store,
                dispute_id,
                &tx.sender,
                *decision,
                timestamp,
                self.reward_config.dispute_won,
                self.dispute_vote_threshold,
            ),

            // ── RCW Token ──
            TxPayload::TransferRCW { to, amount, memo } => {
                modules::token::transfer(&self.store, &tx.sender, to, *amount, memo)
            }

            TxPayload::SpendRCW { amount, purpose } => {
                modules::token::spend(&self.store, &tx.sender, *amount, purpose)
            }

            // ── CTP: Anchor ──
            TxPayload::AnchorMerkleRoot {
                batch_id,
                merkle_root,
                entry_count,
                from_entry_id,
                to_entry_id,
            } => {
                if !self.platform_keys.contains(&tx.sender) {
                    return Err("Unauthorized: only platform can anchor".to_string());
                }
                if self.store.get_anchor(batch_id)?.is_some() {
                    return Err("Anchor batch already recorded".to_string());
                }
                let record = AnchorRecord {
                    batch_id: *batch_id,
                    merkle_root: *merkle_root,
                    entry_count: *entry_count,
                    from_entry_id: *from_entry_id,
                    to_entry_id: *to_entry_id,
                    anchored_at: timestamp,
                };
                self.store.set_anchor(batch_id, &record)?;
                Ok(vec![Event::AnchorRecorded {
                    batch_id: *batch_id,
                    merkle_root: *merkle_root,
                    entry_count: *entry_count,
                }])
            }
        }
    }

    /// Execute all transactions in a block, verifying signatures and state root
    pub fn apply_block(&mut self, block: &Block) -> Result<Vec<Event>, String> {
        let mut all_events = Vec::new();

        for tx in &block.transactions {
            // Verify transaction signature before execution
            if !Self::verify_tx_signature(tx) {
                warn!("Invalid tx signature in block {}, skipping", block.header.height);
                continue;
            }

            match self.execute(tx, block.header.timestamp) {
                Ok(events) => all_events.extend(events),
                Err(e) => {
                    info!("Transaction failed in block {}: {e}", block.header.height);
                }
            }
        }

        // Verify state root matches after execution
        let computed_root = self.store.compute_state_root();
        if block.header.state_root != EMPTY_HASH && computed_root != block.header.state_root {
            return Err(format!(
                "State root mismatch at height {}: expected {}, computed {}",
                block.header.height,
                hex::encode(&block.header.state_root[..8]),
                hex::encode(&computed_root[..8]),
            ));
        }

        // Store the block
        self.store.put_block(block)?;

        Ok(all_events)
    }

    /// Get reference to store for read operations
    pub fn store(&self) -> &Store {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(name: &str) -> (Store, String) {
        let path = format!("/tmp/rcw_test_state_{}", name);
        let _ = std::fs::remove_dir_all(&path);
        let store = Store::open(&path).unwrap();
        (store, path)
    }

    fn test_reward_config() -> RewardConfig {
        RewardConfig {
            settlement_recorded: 5,
            escrow_completed: 20,
            trust_90_monthly: 100,
            rating_submitted: 2,
            dispute_won: 50,
            referral: 50,
        }
    }

    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn make_tx(payload: TxPayload, sender: Id) -> Transaction {
        Transaction {
            payload,
            sender,
            signature: Signature::default(),
            timestamp: 1000,
            nonce: NONCE_COUNTER.fetch_add(1, Ordering::Relaxed),
        }
    }

    // ── Participant Tests ──

    #[test]
    fn test_participant_register() {
        let (store, path) = test_store("participant_register");
        let mut sm = StateMachine::new(store, test_reward_config());

        let id = [1u8; 32];
        let tx = make_tx(
            TxPayload::RegisterParticipant {
                id,
                p_type: ParticipantType::Seller,
                metadata: "test seller".to_string(),
            },
            id, // sender == id (self-registration)
        );

        let events = sm.execute(&tx, 1000).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], Event::ParticipantRegistered { id: eid, p_type: 1 } if *eid == id));

        let p = sm.store().get_participant(&id).unwrap().unwrap();
        assert!(p.is_active);
        assert_eq!(p.p_type, ParticipantType::Seller as u8);
        assert_eq!(p.metadata, "test seller");

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_participant_register_unauthorized() {
        let (store, path) = test_store("participant_register_unauth");
        let mut sm = StateMachine::new(store, test_reward_config());

        let id = [1u8; 32];
        let other = [2u8; 32];
        let tx = make_tx(
            TxPayload::RegisterParticipant {
                id,
                p_type: ParticipantType::Seller,
                metadata: "test".to_string(),
            },
            other, // sender != id -> unauthorized
        );

        let err = sm.execute(&tx, 1000).unwrap_err();
        assert!(err.contains("Unauthorized"));

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_participant_duplicate_rejected() {
        let (store, path) = test_store("participant_dup");
        let mut sm = StateMachine::new(store, test_reward_config());

        let id = [1u8; 32];
        let tx1 = make_tx(
            TxPayload::RegisterParticipant {
                id,
                p_type: ParticipantType::Buyer,
                metadata: "buyer".to_string(),
            },
            id,
        );

        sm.execute(&tx1, 1000).unwrap();

        let tx2 = make_tx(
            TxPayload::RegisterParticipant {
                id,
                p_type: ParticipantType::Buyer,
                metadata: "buyer".to_string(),
            },
            id,
        );
        let err = sm.execute(&tx2, 2000).unwrap_err();
        assert!(err.contains("already exists"));

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_participant_update_and_deactivate() {
        let (store, path) = test_store("participant_lifecycle");
        let mut sm = StateMachine::new(store, test_reward_config());

        let id = [1u8; 32];
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant {
                id,
                p_type: ParticipantType::Seller,
                metadata: "v1".to_string(),
            },
            id,
        ), 1000).unwrap();

        // Update (sender == id)
        sm.execute(&make_tx(
            TxPayload::UpdateParticipant {
                id,
                metadata: "v2".to_string(),
            },
            id,
        ), 2000).unwrap();

        let p = sm.store().get_participant(&id).unwrap().unwrap();
        assert_eq!(p.metadata, "v2");
        assert_eq!(p.last_activity_at, 2000);

        // Unauthorized update (sender != id)
        let other = [2u8; 32];
        let err = sm.execute(&make_tx(
            TxPayload::UpdateParticipant {
                id,
                metadata: "hacked".to_string(),
            },
            other,
        ), 3000).unwrap_err();
        assert!(err.contains("Unauthorized"));

        // Deactivate (sender == id)
        sm.execute(&make_tx(
            TxPayload::DeactivateParticipant { id },
            id,
        ), 3000).unwrap();

        let p = sm.store().get_participant(&id).unwrap().unwrap();
        assert!(!p.is_active);

        let _ = std::fs::remove_dir_all(path);
    }

    // ── Settlement Tests ──

    #[test]
    fn test_settlement_with_reward() {
        let (store, path) = test_store("settlement_reward");
        let mut sm = StateMachine::new(store, test_reward_config());

        let pid = [1u8; 32];
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant {
                id: pid,
                p_type: ParticipantType::Seller,
                metadata: "seller".to_string(),
            },
            pid,
        ), 1000).unwrap();

        let record_id = [10u8; 32];
        let events = sm.execute(&make_tx(
            TxPayload::RecordSettlement {
                participant_id: pid,
                record: SettlementData {
                    record_id,
                    gross_amount: 100_000,
                    platform_fee: 3_000,
                    net_amount: 97_000,
                    currency: *b"KRW\0",
                    settled_at: 900,
                },
            },
            pid, // sender == participant_id
        ), 1000).unwrap();

        // SettlementRecorded + RCWMinted
        assert_eq!(events.len(), 2);

        let p = sm.store().get_participant(&pid).unwrap().unwrap();
        assert_eq!(p.total_tx, 1);
        assert_eq!(p.success_tx, 1);
        assert_eq!(p.total_volume, 100_000);

        let bal = sm.store().get_balance(&pid).unwrap();
        assert_eq!(bal.earned, 5); // settlement_recorded reward

        let record = sm.store().get_settlement(&record_id).unwrap().unwrap();
        assert_eq!(record.net_amount, 97_000);

        let _ = std::fs::remove_dir_all(path);
    }

    // ── Escrow Tests ──

    #[test]
    fn test_escrow_create_and_release() {
        let (store, path) = test_store("escrow_release");
        let mut sm = StateMachine::new(store, test_reward_config());

        let buyer_id = [1u8; 32];
        let seller_id = [2u8; 32];
        let escrow_id = [10u8; 32];

        // Register both parties
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: buyer_id, p_type: ParticipantType::Buyer, metadata: "b".to_string() },
            buyer_id,
        ), 1000).unwrap();
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: seller_id, p_type: ParticipantType::Seller, metadata: "s".to_string() },
            seller_id,
        ), 1000).unwrap();

        // Create escrow (sender = buyer)
        let events = sm.execute(&make_tx(
            TxPayload::CreateEscrow { escrow_id, buyer: buyer_id, seller: seller_id, amount: 50000, expires_at: 99999 },
            buyer_id,
        ), 1000).unwrap();
        assert_eq!(events.len(), 1);

        let escrow = sm.store().get_escrow(&escrow_id).unwrap().unwrap();
        assert_eq!(escrow.state, EscrowState::Created);

        // Release (sender = buyer confirms delivery)
        let evidence = [0xABu8; 32];
        let events = sm.execute(&make_tx(
            TxPayload::ReleaseEscrow { escrow_id, evidence_hash: evidence },
            buyer_id,
        ), 2000).unwrap();

        // EscrowReleased + 2x RCWMinted (buyer + seller rewards)
        assert_eq!(events.len(), 3);

        let escrow = sm.store().get_escrow(&escrow_id).unwrap().unwrap();
        assert_eq!(escrow.state, EscrowState::Released);

        let buyer_bal = sm.store().get_balance(&buyer_id).unwrap();
        assert_eq!(buyer_bal.earned, 20); // escrow_completed reward

        let seller_bal = sm.store().get_balance(&seller_id).unwrap();
        assert_eq!(seller_bal.earned, 20);

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_escrow_unauthorized_release() {
        let (store, path) = test_store("escrow_unauth_release");
        let mut sm = StateMachine::new(store, test_reward_config());

        let buyer_id = [1u8; 32];
        let seller_id = [2u8; 32];
        let escrow_id = [10u8; 32];

        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: buyer_id, p_type: ParticipantType::Buyer, metadata: "b".to_string() },
            buyer_id,
        ), 1000).unwrap();
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: seller_id, p_type: ParticipantType::Seller, metadata: "s".to_string() },
            seller_id,
        ), 1000).unwrap();

        sm.execute(&make_tx(
            TxPayload::CreateEscrow { escrow_id, buyer: buyer_id, seller: seller_id, amount: 50000, expires_at: 99999 },
            buyer_id,
        ), 1000).unwrap();

        // Seller tries to release -> unauthorized
        let err = sm.execute(&make_tx(
            TxPayload::ReleaseEscrow { escrow_id, evidence_hash: [0xABu8; 32] },
            seller_id,
        ), 2000).unwrap_err();
        assert!(err.contains("Unauthorized"));

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_escrow_refund() {
        let (store, path) = test_store("escrow_refund");
        let mut sm = StateMachine::new(store, test_reward_config());

        let buyer_id = [1u8; 32];
        let seller_id = [2u8; 32];
        let escrow_id = [10u8; 32];

        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: buyer_id, p_type: ParticipantType::Buyer, metadata: "b".to_string() },
            buyer_id,
        ), 1000).unwrap();
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: seller_id, p_type: ParticipantType::Seller, metadata: "s".to_string() },
            seller_id,
        ), 1000).unwrap();

        sm.execute(&make_tx(
            TxPayload::CreateEscrow { escrow_id, buyer: buyer_id, seller: seller_id, amount: 50000, expires_at: 99999 },
            buyer_id,
        ), 1000).unwrap();

        // Buyer refunds
        sm.execute(&make_tx(
            TxPayload::RefundEscrow { escrow_id },
            buyer_id,
        ), 2000).unwrap();

        let escrow = sm.store().get_escrow(&escrow_id).unwrap().unwrap();
        assert_eq!(escrow.state, EscrowState::Refunded);

        let seller = sm.store().get_participant(&seller_id).unwrap().unwrap();
        assert_eq!(seller.total_tx, 1);

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_escrow_expired_refund_by_anyone() {
        let (store, path) = test_store("escrow_expired_refund");
        let mut sm = StateMachine::new(store, test_reward_config());

        let buyer_id = [1u8; 32];
        let seller_id = [2u8; 32];
        let escrow_id = [10u8; 32];
        let anyone = [99u8; 32];

        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: buyer_id, p_type: ParticipantType::Buyer, metadata: "b".to_string() },
            buyer_id,
        ), 1000).unwrap();
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: seller_id, p_type: ParticipantType::Seller, metadata: "s".to_string() },
            seller_id,
        ), 1000).unwrap();

        sm.execute(&make_tx(
            TxPayload::CreateEscrow { escrow_id, buyer: buyer_id, seller: seller_id, amount: 50000, expires_at: 5000 },
            buyer_id,
        ), 1000).unwrap();

        // Anyone can refund after expiry (timestamp > expires_at)
        sm.execute(&make_tx(
            TxPayload::RefundEscrow { escrow_id },
            anyone,
        ), 6000).unwrap();

        let escrow = sm.store().get_escrow(&escrow_id).unwrap().unwrap();
        assert_eq!(escrow.state, EscrowState::Refunded);

        let _ = std::fs::remove_dir_all(path);
    }

    // ── Dispute Tests ──

    #[test]
    fn test_dispute_full_flow() {
        let (store, path) = test_store("dispute_flow");
        let mut sm = StateMachine::new(store, test_reward_config());

        let buyer_id = [1u8; 32];
        let seller_id = [2u8; 32];
        let escrow_id = [10u8; 32];
        let dispute_id = [20u8; 32];

        // Setup
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: buyer_id, p_type: ParticipantType::Buyer, metadata: "b".to_string() },
            buyer_id,
        ), 1000).unwrap();
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: seller_id, p_type: ParticipantType::Seller, metadata: "s".to_string() },
            seller_id,
        ), 1000).unwrap();
        sm.execute(&make_tx(
            TxPayload::CreateEscrow { escrow_id, buyer: buyer_id, seller: seller_id, amount: 50000, expires_at: 99999 },
            buyer_id,
        ), 1000).unwrap();

        // Raise dispute (buyer raises against seller)
        let evidence1 = [0xAAu8; 32];
        sm.execute(&make_tx(
            TxPayload::RaiseDispute { dispute_id, escrow_id, reason: DisputeReason::NotDelivered, evidence_hash: evidence1 },
            buyer_id,
        ), 2000).unwrap();

        let escrow = sm.store().get_escrow(&escrow_id).unwrap().unwrap();
        assert_eq!(escrow.state, EscrowState::Disputed);

        // Dispute starts in Raised state
        let dispute = sm.store().get_dispute(&dispute_id).unwrap().unwrap();
        assert_eq!(dispute.state, DisputeState::Raised);

        // Seller's dispute count incremented
        let seller = sm.store().get_participant(&seller_id).unwrap().unwrap();
        assert_eq!(seller.dispute_count, 1);

        // Submit evidence (transitions Raised -> Evidence)
        let evidence2 = [0xBBu8; 32];
        sm.execute(&make_tx(
            TxPayload::SubmitEvidence { dispute_id, evidence_hash: evidence2 },
            seller_id,
        ), 3000).unwrap();

        let dispute = sm.store().get_dispute(&dispute_id).unwrap().unwrap();
        assert_eq!(dispute.state, DisputeState::Evidence);
        assert_eq!(dispute.evidence_hashes.len(), 2);

        // Register 3 arbiters for voting
        let voter1 = [31u8; 32];
        let voter2 = [32u8; 32];
        let voter3 = [33u8; 32];

        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: voter1, p_type: ParticipantType::Arbiter, metadata: "a1".to_string() },
            voter1,
        ), 3500).unwrap();
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: voter2, p_type: ParticipantType::Arbiter, metadata: "a2".to_string() },
            voter2,
        ), 3500).unwrap();
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: voter3, p_type: ParticipantType::Arbiter, metadata: "a3".to_string() },
            voter3,
        ), 3500).unwrap();

        // Vote 3 times (favor buyer wins)
        sm.execute(&make_tx(
            TxPayload::VoteDispute { dispute_id, decision: DisputeDecision::FavorBuyer },
            voter1,
        ), 4000).unwrap();

        sm.execute(&make_tx(
            TxPayload::VoteDispute { dispute_id, decision: DisputeDecision::FavorBuyer },
            voter2,
        ), 4000).unwrap();

        let events = sm.execute(&make_tx(
            TxPayload::VoteDispute { dispute_id, decision: DisputeDecision::FavorSeller },
            voter3,
        ), 4000).unwrap();

        // Should have DisputeResolved + RCWMinted
        assert!(events.iter().any(|e| matches!(e, Event::DisputeResolved { .. })));

        let dispute = sm.store().get_dispute(&dispute_id).unwrap().unwrap();
        assert_eq!(dispute.state, DisputeState::Resolved);
        assert_eq!(dispute.resolution, Some(0)); // FavorBuyer (2 vs 1)

        // Buyer won, gets dispute_won reward
        let buyer = sm.store().get_participant(&buyer_id).unwrap().unwrap();
        assert_eq!(buyer.dispute_won, 1);

        let buyer_bal = sm.store().get_balance(&buyer_id).unwrap();
        assert_eq!(buyer_bal.earned, 50); // dispute_won reward

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_dispute_unauthorized_vote() {
        let (store, path) = test_store("dispute_unauth_vote");
        let mut sm = StateMachine::new(store, test_reward_config());

        let buyer_id = [1u8; 32];
        let seller_id = [2u8; 32];
        let escrow_id = [10u8; 32];
        let dispute_id = [20u8; 32];
        let non_arbiter = [50u8; 32];

        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: buyer_id, p_type: ParticipantType::Buyer, metadata: "b".to_string() },
            buyer_id,
        ), 1000).unwrap();
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: seller_id, p_type: ParticipantType::Seller, metadata: "s".to_string() },
            seller_id,
        ), 1000).unwrap();
        // Register non_arbiter as Seller (not Arbiter)
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: non_arbiter, p_type: ParticipantType::Seller, metadata: "na".to_string() },
            non_arbiter,
        ), 1000).unwrap();

        sm.execute(&make_tx(
            TxPayload::CreateEscrow { escrow_id, buyer: buyer_id, seller: seller_id, amount: 50000, expires_at: 99999 },
            buyer_id,
        ), 1000).unwrap();

        sm.execute(&make_tx(
            TxPayload::RaiseDispute { dispute_id, escrow_id, reason: DisputeReason::NotDelivered, evidence_hash: [0xAAu8; 32] },
            buyer_id,
        ), 2000).unwrap();

        // Non-arbiter tries to vote -> rejected
        let err = sm.execute(&make_tx(
            TxPayload::VoteDispute { dispute_id, decision: DisputeDecision::FavorBuyer },
            non_arbiter,
        ), 3000).unwrap_err();
        assert!(err.contains("Arbiter"));

        let _ = std::fs::remove_dir_all(path);
    }

    // ── Token Tests ──

    #[test]
    fn test_token_transfer() {
        let (store, path) = test_store("token_transfer");
        let mut sm = StateMachine::new(store, test_reward_config());

        let from_id = [1u8; 32];
        let to_id = [2u8; 32];

        // Mint to sender first
        modules::token::mint(sm.store(), &from_id, 100, "setup").unwrap();
        assert_eq!(sm.store().get_balance(&from_id).unwrap().earned, 100);

        // Transfer
        let events = sm.execute(&make_tx(
            TxPayload::TransferRCW { to: to_id, amount: 30, memo: "payment".to_string() },
            from_id,
        ), 1000).unwrap();

        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], Event::RCWTransferred { from, to, amount: 30 } if *from == from_id && *to == to_id));

        let from_bal = sm.store().get_balance(&from_id).unwrap();
        assert_eq!(from_bal.earned, 70);

        let to_bal = sm.store().get_balance(&to_id).unwrap();
        assert_eq!(to_bal.earned, 30);

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_token_insufficient_balance() {
        let (store, path) = test_store("token_insufficient");
        let mut sm = StateMachine::new(store, test_reward_config());

        let from_id = [1u8; 32];
        let to_id = [2u8; 32];

        modules::token::mint(sm.store(), &from_id, 10, "setup").unwrap();

        let err = sm.execute(&make_tx(
            TxPayload::TransferRCW { to: to_id, amount: 100, memo: "too much".to_string() },
            from_id,
        ), 1000).unwrap_err();

        assert!(err.contains("Insufficient balance"));

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_token_earned_first_deduction() {
        let (store, path) = test_store("token_deduction_order");
        let mut sm = StateMachine::new(store, test_reward_config());

        let id = [1u8; 32];

        // Set up balance: 30 earned + 70 purchased
        modules::token::mint(sm.store(), &id, 30, "earn").unwrap();
        let mut bal = sm.store().get_balance(&id).unwrap();
        bal.purchased = 70;
        sm.store().set_balance(&id, &bal).unwrap();

        // Transfer 50: should take 30 from earned, 20 from purchased
        sm.execute(&make_tx(
            TxPayload::TransferRCW { to: [2u8; 32], amount: 50, memo: "test".to_string() },
            id,
        ), 1000).unwrap();

        let bal = sm.store().get_balance(&id).unwrap();
        assert_eq!(bal.earned, 0);
        assert_eq!(bal.purchased, 50);

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_spend_rcw() {
        let (store, path) = test_store("spend_rcw");
        let mut sm = StateMachine::new(store, test_reward_config());

        let id = [1u8; 32];
        modules::token::mint(sm.store(), &id, 100, "setup").unwrap();

        let events = sm.execute(&make_tx(
            TxPayload::SpendRCW { amount: 40, purpose: "ai_tool".to_string() },
            id,
        ), 1000).unwrap();

        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], Event::RCWSpent { from, amount: 40, .. } if *from == id));

        let bal = sm.store().get_balance(&id).unwrap();
        assert_eq!(bal.earned, 60);

        let _ = std::fs::remove_dir_all(path);
    }

    // ── Nonce Replay Protection Test ──

    #[test]
    fn test_nonce_replay_rejected() {
        let (store, path) = test_store("nonce_replay");
        let mut sm = StateMachine::new(store, test_reward_config());

        let sender = [1u8; 32];

        // First tx with nonce 1 succeeds
        let tx1 = Transaction {
            payload: TxPayload::RegisterParticipant {
                id: sender,
                p_type: ParticipantType::Seller,
                metadata: "seller".to_string(),
            },
            sender,
            signature: Signature::default(),
            timestamp: 1000,
            nonce: 1,
        };
        sm.execute(&tx1, 1000).unwrap();

        // Replay same nonce 1 rejected
        let id2 = [3u8; 32];
        let tx_replay = Transaction {
            payload: TxPayload::RegisterParticipant {
                id: id2,
                p_type: ParticipantType::Buyer,
                metadata: "buyer".to_string(),
            },
            sender: id2,
            signature: Signature::default(),
            timestamp: 1000,
            nonce: 1,
        };
        // This will succeed because it's a different sender (id2), nonce 1 is new for id2
        sm.execute(&tx_replay, 1000).unwrap();

        // Replay same sender + nonce rejected
        let tx_replay2 = Transaction {
            payload: TxPayload::UpdateParticipant {
                id: sender,
                metadata: "hacked".to_string(),
            },
            sender,
            signature: Signature::default(),
            timestamp: 1000,
            nonce: 1,
        };
        let err = sm.execute(&tx_replay2, 1000).unwrap_err();
        assert!(err.contains("Nonce too low"));

        // Nonce 2 succeeds
        let tx2 = Transaction {
            payload: TxPayload::UpdateParticipant {
                id: sender,
                metadata: "updated".to_string(),
            },
            sender,
            signature: Signature::default(),
            timestamp: 1000,
            nonce: 2,
        };
        sm.execute(&tx2, 1000).unwrap();

        let _ = std::fs::remove_dir_all(path);
    }

    // ── Block Application Test ──

    fn make_signed_tx(payload: TxPayload, private_key: &[u8; 32], public_key: Id, nonce: u64) -> Transaction {
        let payload_bytes = bincode::serialize(&payload).unwrap();
        let sig = rc_crypto::sign(&payload_bytes, private_key);
        Transaction {
            payload,
            sender: public_key,
            signature: Signature(sig),
            timestamp: 2000,
            nonce,
        }
    }

    #[test]
    fn test_apply_block() {
        let (store, path) = test_store("apply_block");
        let mut sm = StateMachine::new(store, test_reward_config());

        // Create genesis first
        let genesis = Block::genesis(1000, [0u8; 32]);
        sm.store().put_block(&genesis).unwrap();

        // Generate real keypairs for proper signature verification
        let (pub1, priv1) = rc_crypto::generate_keypair();
        let (pub2, priv2) = rc_crypto::generate_keypair();

        let payload1 = TxPayload::RegisterParticipant {
            id: pub1,
            p_type: ParticipantType::Seller,
            metadata: "seller".to_string(),
        };
        let payload2 = TxPayload::RegisterParticipant {
            id: pub2,
            p_type: ParticipantType::Buyer,
            metadata: "buyer".to_string(),
        };

        let txs = vec![
            make_signed_tx(payload1, &priv1, pub1, 1),
            make_signed_tx(payload2, &priv2, pub2, 1),
        ];

        let block = Block {
            header: BlockHeader {
                height: 1,
                prev_hash: EMPTY_HASH,
                timestamp: 2000,
                tx_count: 2,
                tx_hash: EMPTY_HASH,
                state_root: EMPTY_HASH,
                proposer: [0u8; 32],
            },
            transactions: txs,
            signatures: vec![],
        };

        let events = sm.apply_block(&block).unwrap();
        assert_eq!(events.len(), 2); // 2 registrations

        // Block stored
        assert_eq!(sm.store().get_latest_height(), 1);
        let loaded = sm.store().get_block(1).unwrap().unwrap();
        assert_eq!(loaded.header.tx_count, 2);

        // State updated
        assert!(sm.store().get_participant(&pub1).unwrap().is_some());
        assert!(sm.store().get_participant(&pub2).unwrap().is_some());

        let _ = std::fs::remove_dir_all(path);
    }

    // ── Rating Test ──

    #[test]
    fn test_rating_and_trust_score() {
        let (store, path) = test_store("rating_trust");
        let mut sm = StateMachine::new(store, test_reward_config());

        let pid = [1u8; 32];
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: pid, p_type: ParticipantType::Seller, metadata: "s".to_string() },
            pid,
        ), 1000).unwrap();

        // Record a settlement first
        sm.execute(&make_tx(
            TxPayload::RecordSettlement {
                participant_id: pid,
                record: SettlementData {
                    record_id: [10u8; 32],
                    gross_amount: 10000,
                    platform_fee: 300,
                    net_amount: 9700,
                    currency: *b"KRW\0",
                    settled_at: 900,
                },
            },
            pid,
        ), 1000).unwrap();

        // Record rating
        let events = sm.execute(&make_tx(
            TxPayload::RecordRating { participant_id: pid, rating: 450, success: true },
            [0u8; 32], // rating can be submitted by anyone
        ), 2000).unwrap();

        assert!(events.iter().any(|e| matches!(e, Event::RatingRecorded { .. })));

        let p = sm.store().get_participant(&pid).unwrap().unwrap();
        assert_eq!(p.rating_count, 1);
        assert_eq!(p.rating_sum, 450);

        let score = compute_trust_score(&p);
        assert!(score > 0);

        let _ = std::fs::remove_dir_all(path);
    }

    // ── Trust Score Maturity Tests ──

    #[test]
    fn test_trust_score_no_rating_gives_zero_rating_component() {
        let with_rating = Participant {
            total_tx: 10,
            success_tx: 10,
            dispute_count: 0,
            rating_sum: 450,
            rating_count: 1,
            total_volume: 50_000,
            registered_at: 0,
            last_activity_at: 86400 * 30,
            ..Default::default()
        };
        let without_rating = Participant {
            rating_sum: 0,
            rating_count: 0,
            ..with_rating.clone()
        };

        let score_with = compute_trust_score(&with_rating);
        let score_without = compute_trust_score(&without_rating);
        assert!(score_with > score_without, "rating should increase score");
        // 10 tx → maturity 60%. No rating → rating_score = 0.
        // raw_total without rating: 10000*35 + 10000*25 + 0*20 + 2500*10 + 2000*10 = 645000
        // 645000 * 6000 / 10000 / 100 = 3870
        assert_eq!(score_without, 3870);
    }

    #[test]
    fn test_trust_score_maturity_factor_scales() {
        let base = Participant {
            dispute_count: 0,
            rating_sum: 0,
            rating_count: 0,
            total_volume: 10_000_000,
            registered_at: 0,
            last_activity_at: 86400 * 400,
            ..Default::default()
        };

        // 5 tx → 30% maturity
        let s5 = compute_trust_score(&Participant { total_tx: 5, success_tx: 5, ..base.clone() });
        // 50 tx → 80% maturity
        let s50 = compute_trust_score(&Participant { total_tx: 50, success_tx: 50, ..base.clone() });
        // 100 tx → 100% maturity
        let s100 = compute_trust_score(&Participant { total_tx: 100, success_tx: 100, ..base.clone() });

        assert!(s5 < s50, "5tx ({}) should score less than 50tx ({})", s5, s50);
        assert!(s50 < s100, "50tx ({}) should score less than 100tx ({})", s50, s100);
        assert!(s5 > 0, "5tx score should be nonzero");
    }

    // ── Dispute Loser Penalty Tests ──

    #[test]
    fn test_dispute_raiser_loses_gets_double_penalty() {
        let (store, path) = test_store("dispute_raiser_loses");
        let mut sm = StateMachine::new(store, test_reward_config());

        let buyer_id = [1u8; 32];
        let seller_id = [2u8; 32];
        let escrow_id = [10u8; 32];
        let dispute_id = [20u8; 32];

        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: buyer_id, p_type: ParticipantType::Buyer, metadata: "b".to_string() },
            buyer_id,
        ), 1000).unwrap();
        sm.execute(&make_tx(
            TxPayload::RegisterParticipant { id: seller_id, p_type: ParticipantType::Seller, metadata: "s".to_string() },
            seller_id,
        ), 1000).unwrap();
        sm.execute(&make_tx(
            TxPayload::CreateEscrow { escrow_id, buyer: buyer_id, seller: seller_id, amount: 50000, expires_at: 99999 },
            buyer_id,
        ), 1000).unwrap();

        // Buyer raises dispute
        sm.execute(&make_tx(
            TxPayload::RaiseDispute { dispute_id, escrow_id, reason: DisputeReason::NotDelivered, evidence_hash: [0xAAu8; 32] },
            buyer_id,
        ), 2000).unwrap();

        // After raise: seller.dispute_count = 1, buyer.dispute_count = 0
        assert_eq!(sm.store().get_participant(&seller_id).unwrap().unwrap().dispute_count, 1);
        assert_eq!(sm.store().get_participant(&buyer_id).unwrap().unwrap().dispute_count, 0);

        let voter1 = [31u8; 32];
        let voter2 = [32u8; 32];
        let voter3 = [33u8; 32];
        for v in [voter1, voter2, voter3] {
            sm.execute(&make_tx(
                TxPayload::RegisterParticipant { id: v, p_type: ParticipantType::Arbiter, metadata: "a".to_string() },
                v,
            ), 3000).unwrap();
        }

        // Seller wins (buyer loses as raiser → 2x penalty)
        sm.execute(&make_tx(TxPayload::VoteDispute { dispute_id, decision: DisputeDecision::FavorSeller }, voter1), 4000).unwrap();
        sm.execute(&make_tx(TxPayload::VoteDispute { dispute_id, decision: DisputeDecision::FavorSeller }, voter2), 4000).unwrap();
        sm.execute(&make_tx(TxPayload::VoteDispute { dispute_id, decision: DisputeDecision::FavorBuyer }, voter3), 4000).unwrap();

        let buyer = sm.store().get_participant(&buyer_id).unwrap().unwrap();
        // Buyer was raiser and lost → +2 penalty
        assert_eq!(buyer.dispute_count, 2);
        assert_eq!(buyer.dispute_won, 0);

        let seller = sm.store().get_participant(&seller_id).unwrap().unwrap();
        // Seller was wrongly targeted → raise-time +1 reversed to 0, then won
        assert_eq!(seller.dispute_count, 0);
        assert_eq!(seller.dispute_won, 1);

        let _ = std::fs::remove_dir_all(path);
    }

    // ── Anchor Tests ──

    #[test]
    fn test_anchor_merkle_root() {
        let (store, path) = test_store("anchor_merkle");
        let platform_key = [42u8; 32];
        let mut sm = StateMachine::new(store, test_reward_config())
            .with_platform_keys(vec![platform_key]);

        let batch_id = [100u8; 32];
        let merkle_root = [0xABu8; 32];

        let events = sm.execute(&make_tx(
            TxPayload::AnchorMerkleRoot {
                batch_id,
                merkle_root,
                entry_count: 500,
                from_entry_id: 1,
                to_entry_id: 500,
            },
            platform_key,
        ), 5000).unwrap();

        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], Event::AnchorRecorded { batch_id: bid, entry_count: 500, .. } if *bid == batch_id));

        let record = sm.store().get_anchor(&batch_id).unwrap().unwrap();
        assert_eq!(record.merkle_root, merkle_root);
        assert_eq!(record.entry_count, 500);
        assert_eq!(record.from_entry_id, 1);
        assert_eq!(record.to_entry_id, 500);
        assert_eq!(record.anchored_at, 5000);

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_anchor_unauthorized_rejected() {
        let (store, path) = test_store("anchor_unauth");
        let platform_key = [42u8; 32];
        let random_sender = [99u8; 32];
        let mut sm = StateMachine::new(store, test_reward_config())
            .with_platform_keys(vec![platform_key]);

        let err = sm.execute(&make_tx(
            TxPayload::AnchorMerkleRoot {
                batch_id: [100u8; 32],
                merkle_root: [0xABu8; 32],
                entry_count: 10,
                from_entry_id: 1,
                to_entry_id: 10,
            },
            random_sender,
        ), 5000).unwrap_err();

        assert!(err.contains("Unauthorized"));

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_anchor_duplicate_rejected() {
        let (store, path) = test_store("anchor_dup");
        let platform_key = [42u8; 32];
        let mut sm = StateMachine::new(store, test_reward_config())
            .with_platform_keys(vec![platform_key]);

        let batch_id = [100u8; 32];

        sm.execute(&make_tx(
            TxPayload::AnchorMerkleRoot {
                batch_id,
                merkle_root: [0xAAu8; 32],
                entry_count: 10,
                from_entry_id: 1,
                to_entry_id: 10,
            },
            platform_key,
        ), 5000).unwrap();

        let err = sm.execute(&make_tx(
            TxPayload::AnchorMerkleRoot {
                batch_id,
                merkle_root: [0xBBu8; 32],
                entry_count: 20,
                from_entry_id: 11,
                to_entry_id: 30,
            },
            platform_key,
        ), 6000).unwrap_err();

        assert!(err.contains("already recorded"));

        let _ = std::fs::remove_dir_all(path);
    }
}
