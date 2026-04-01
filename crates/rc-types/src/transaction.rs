use serde::{Deserialize, Serialize};
use crate::{Id, Signature};

/// A signed transaction submitted to the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction payload
    pub payload: TxPayload,
    /// Sender's public key (Id)
    pub sender: Id,
    /// Ed25519 signature of serialized payload
    pub signature: Signature,
    /// Unix timestamp (milliseconds)
    pub timestamp: i64,
    /// Client-provided nonce for dedup
    pub nonce: u64,
}

/// All possible transaction types in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxPayload {
    // ── CTP: Participant ──
    RegisterParticipant {
        id: Id,
        p_type: ParticipantType,
        metadata: String,
    },
    UpdateParticipant {
        id: Id,
        metadata: String,
    },
    DeactivateParticipant {
        id: Id,
    },

    // ── CTP: Settlement ──
    RecordSettlement {
        participant_id: Id,
        record: SettlementData,
    },
    RecordRating {
        participant_id: Id,
        rating: u16,
        success: bool,
    },

    // ── CTP: Escrow ──
    CreateEscrow {
        escrow_id: Id,
        buyer: Id,
        seller: Id,
        amount: u64,
        expires_at: i64,
    },
    ReleaseEscrow {
        escrow_id: Id,
        evidence_hash: [u8; 32],
    },
    RefundEscrow {
        escrow_id: Id,
    },

    // ── CTP: Dispute ──
    RaiseDispute {
        dispute_id: Id,
        escrow_id: Id,
        reason: DisputeReason,
        evidence_hash: [u8; 32],
    },
    SubmitEvidence {
        dispute_id: Id,
        evidence_hash: [u8; 32],
    },
    VoteDispute {
        dispute_id: Id,
        decision: DisputeDecision,
    },

    // ── RCW Token ──
    TransferRCW {
        to: Id,
        amount: u64,
        memo: String,
    },
    SpendRCW {
        amount: u64,
        purpose: String,
    },
}

/// Participant types across all domains
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ParticipantType {
    // E-commerce
    Seller = 1,
    Buyer = 2,
    // Content
    Author = 10,
    ContentWork = 11,
    // Investment
    Franchisee = 20,
    Investor = 21,
    Host = 22,
    // Marketing
    Influencer = 30,
    Brand = 31,
    Agency = 32,
    // Service
    ServiceProvider = 40,
    // AI Agents
    BuyerAgent = 50,
    SellerAgent = 51,
    MatchingAgent = 52,
    Arbiter = 54,
}

/// Settlement data recorded on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementData {
    pub record_id: Id,
    pub gross_amount: u64,
    pub platform_fee: u64,
    pub net_amount: u64,
    pub currency: [u8; 4],
    pub settled_at: i64,
}

/// Dispute reasons
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DisputeReason {
    NotDelivered = 0,
    Damaged = 1,
    NotAsDescribed = 2,
    Unauthorized = 3,
    Other = 99,
}

/// Dispute resolution decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DisputeDecision {
    FavorBuyer = 0,
    FavorSeller = 1,
    Split = 2,
}
