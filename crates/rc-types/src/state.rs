use serde::{Deserialize, Serialize};
use crate::Id;

/// Participant trust profile stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Participant {
    pub id: Id,
    pub p_type: u8,
    pub metadata: String,
    pub total_tx: u64,
    pub success_tx: u64,
    pub dispute_count: u64,
    pub dispute_won: u64,
    pub rating_sum: u64,
    pub rating_count: u64,
    pub total_volume: u64,
    pub total_settled: u64,
    pub registered_at: i64,
    pub last_activity_at: i64,
    pub is_active: bool,
}

/// RCW token balance
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RCWBalance {
    pub owner: Id,
    pub earned: u64,
    pub purchased: u64,
}

impl RCWBalance {
    pub fn total(&self) -> u64 {
        self.earned + self.purchased
    }
}

/// Escrow state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Escrow {
    pub id: Id,
    pub buyer: Id,
    pub seller: Id,
    pub amount: u64,
    pub state: EscrowState,
    pub created_at: i64,
    pub expires_at: i64,
    pub evidence_hash: Option<[u8; 32]>,
    pub dispute_id: Option<Id>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EscrowState {
    Created = 0,
    Funded = 1,
    Released = 2,
    Refunded = 3,
    Disputed = 4,
}

/// Dispute state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispute {
    pub id: Id,
    pub escrow_id: Id,
    pub raised_by: Id,
    pub reason: u8,
    pub evidence_hashes: Vec<[u8; 32]>,
    pub votes: Vec<DisputeVote>,
    pub state: DisputeState,
    pub resolution: Option<u8>,
    pub raised_at: i64,
    pub resolved_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DisputeState {
    Raised = 0,
    Evidence = 1,
    Voting = 2,
    Resolved = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeVote {
    pub voter: Id,
    pub decision: u8,
    pub voted_at: i64,
}

/// Settlement record stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub record_id: Id,
    pub participant_id: Id,
    pub gross_amount: u64,
    pub platform_fee: u64,
    pub net_amount: u64,
    pub currency: [u8; 4],
    pub settled_at: i64,
    pub recorded_at: i64,
}

/// Anchor record for CTP Merkle root anchoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRecord {
    pub batch_id: Id,
    pub merkle_root: [u8; 32],
    pub entry_count: u64,
    pub from_entry_id: u64,
    pub to_entry_id: u64,
    pub anchored_at: i64,
}

/// Trust Score computation — pure function, no chain dependency
pub fn compute_trust_score(p: &Participant) -> u16 {
    if p.total_tx == 0 {
        return 0;
    }

    const W_SUCCESS: u128 = 35;
    const W_DISPUTE: u128 = 25;
    const W_RATING: u128 = 20;
    const W_VOLUME: u128 = 10;
    const W_LONGEVITY: u128 = 10;

    let success_score = (p.success_tx as u128 * 10000) / p.total_tx as u128;

    let dispute_score = if p.dispute_count > 0 {
        let rate = (p.dispute_count as u128 * 10000) / p.total_tx as u128;
        10000u128.saturating_sub(rate * 3)
    } else {
        10000
    };

    let rating_score = if p.rating_count > 0 {
        (p.rating_sum as u128 * 2000) / p.rating_count as u128
    } else {
        0
    };

    let volume_score = match p.total_volume {
        0 => 0,
        1..=100_000 => 2500,
        100_001..=1_000_000 => 5000,
        1_000_001..=10_000_000 => 7500,
        _ => 10000,
    };

    let days = if p.last_activity_at > p.registered_at {
        (p.last_activity_at - p.registered_at) / 86400
    } else {
        0
    };
    let longevity_score: u128 = match days {
        0..=30 => 2000,
        31..=90 => 4000,
        91..=180 => 6000,
        181..=365 => 8000,
        _ => 10000,
    };

    let raw_total = success_score * W_SUCCESS
        + dispute_score * W_DISPUTE
        + rating_score * W_RATING
        + volume_score * W_VOLUME
        + longevity_score * W_LONGEVITY;

    let maturity_factor: u128 = match p.total_tx {
        0..=9 => 3000,
        10..=49 => 6000,
        50..=99 => 8000,
        _ => 10000,
    };

    (raw_total * maturity_factor / 10000 / 100) as u16
}

/// Events emitted by state transitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    ParticipantRegistered { id: Id, p_type: u8 },
    ParticipantUpdated { id: Id },
    ParticipantDeactivated { id: Id },
    SettlementRecorded { participant_id: Id, record_id: Id },
    RatingRecorded { participant_id: Id, new_score: u16 },
    EscrowCreated { escrow_id: Id, buyer: Id, seller: Id, amount: u64 },
    EscrowReleased { escrow_id: Id },
    EscrowRefunded { escrow_id: Id },
    DisputeRaised { dispute_id: Id, escrow_id: Id },
    DisputeResolved { dispute_id: Id, decision: u8 },
    RCWMinted { to: Id, amount: u64, reason: String },
    RCWTransferred { from: Id, to: Id, amount: u64 },
    RCWSpent { from: Id, amount: u64, purpose: String },
    AnchorRecorded { batch_id: Id, merkle_root: [u8; 32], entry_count: u64 },
}
