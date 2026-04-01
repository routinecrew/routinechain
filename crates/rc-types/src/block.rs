use serde::{Deserialize, Serialize};
use crate::{Hash, Id, Transaction, EMPTY_HASH, Signature};

/// A block in the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub signatures: Vec<NodeSignature>,
}

/// Block header — hashed to produce block identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height (0 = genesis)
    pub height: u64,
    /// blake3 hash of previous block header
    pub prev_hash: Hash,
    /// Unix timestamp (milliseconds)
    pub timestamp: i64,
    /// Number of transactions in this block
    pub tx_count: u32,
    /// blake3 hash of serialized transactions
    pub tx_hash: Hash,
    /// blake3 hash of state after applying this block
    pub state_root: Hash,
    /// Node ID of the block proposer
    pub proposer: Id,
}

/// A validator's signature on a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSignature {
    pub node_id: Id,
    pub signature: Signature,
}

impl Block {
    /// Create the genesis block
    pub fn genesis(timestamp: i64, proposer: Id) -> Self {
        Self {
            header: BlockHeader {
                height: 0,
                prev_hash: EMPTY_HASH,
                timestamp,
                tx_count: 0,
                tx_hash: EMPTY_HASH,
                state_root: EMPTY_HASH,
                proposer,
            },
            transactions: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// Check if this is the genesis block
    pub fn is_genesis(&self) -> bool {
        self.header.height == 0
    }

    /// Number of validator signatures
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}
