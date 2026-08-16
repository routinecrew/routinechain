use rc_types::*;
use rocksdb::{DB, IteratorMode, Options, WriteBatch};
use std::path::Path;
use std::sync::Arc;

/// Key prefixes for different data types
const PREFIX_BLOCK: &[u8] = b"blk/";
const PREFIX_PARTICIPANT: &[u8] = b"prt/";
const PREFIX_SETTLEMENT: &[u8] = b"stl/";
const PREFIX_BALANCE: &[u8] = b"bal/";
const PREFIX_ESCROW: &[u8] = b"esc/";
const PREFIX_DISPUTE: &[u8] = b"dsp/";
const PREFIX_NONCE: &[u8] = b"nnc/";
const PREFIX_ANCHOR: &[u8] = b"anc/";
const KEY_LATEST_HEIGHT: &[u8] = b"meta/latest_height";

/// All state prefixes for state root computation
const STATE_PREFIXES: &[&[u8]] = &[
    PREFIX_PARTICIPANT,
    PREFIX_SETTLEMENT,
    PREFIX_BALANCE,
    PREFIX_ESCROW,
    PREFIX_DISPUTE,
    PREFIX_NONCE,
    PREFIX_ANCHOR,
];

/// RocksDB-backed storage for blocks and state
#[derive(Clone)]
pub struct Store {
    db: Arc<DB>,
}

impl Store {
    /// Open or create the database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path).map_err(|e| e.to_string())?;
        Ok(Self { db: Arc::new(db) })
    }

    // ── Block Storage ──

    pub fn put_block(&self, block: &Block) -> Result<(), String> {
        let key = Self::block_key(block.header.height);
        let value = bincode::serialize(block).map_err(|e| e.to_string())?;
        self.db.put(&key, &value).map_err(|e| e.to_string())?;

        // Update latest height
        let height_bytes = block.header.height.to_be_bytes();
        self.db
            .put(KEY_LATEST_HEIGHT, height_bytes)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn get_block(&self, height: u64) -> Result<Option<Block>, String> {
        let key = Self::block_key(height);
        match self.db.get(&key).map_err(|e| e.to_string())? {
            Some(bytes) => {
                let block = bincode::deserialize(&bytes).map_err(|e| e.to_string())?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    pub fn get_latest_height(&self) -> u64 {
        match self.db.get(KEY_LATEST_HEIGHT) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes[..8].try_into().unwrap())
            }
            _ => 0,
        }
    }

    // ── Participant Storage ──

    pub fn get_participant(&self, id: &Id) -> Result<Option<Participant>, String> {
        self.get_state(PREFIX_PARTICIPANT, id)
    }

    pub fn set_participant(&self, id: &Id, participant: &Participant) -> Result<(), String> {
        self.set_state(PREFIX_PARTICIPANT, id, participant)
    }

    // ── Settlement Storage ──

    pub fn get_settlement(&self, record_id: &Id) -> Result<Option<SettlementRecord>, String> {
        self.get_state(PREFIX_SETTLEMENT, record_id)
    }

    pub fn set_settlement(
        &self,
        record_id: &Id,
        record: &SettlementRecord,
    ) -> Result<(), String> {
        self.set_state(PREFIX_SETTLEMENT, record_id, record)
    }

    // ── RCW Balance Storage ──

    pub fn get_balance(&self, owner: &Id) -> Result<RCWBalance, String> {
        match self.get_state::<RCWBalance>(PREFIX_BALANCE, owner)? {
            Some(bal) => Ok(bal),
            None => Ok(RCWBalance {
                owner: *owner,
                ..Default::default()
            }),
        }
    }

    pub fn set_balance(&self, owner: &Id, balance: &RCWBalance) -> Result<(), String> {
        self.set_state(PREFIX_BALANCE, owner, balance)
    }

    // ── Escrow Storage ──

    pub fn get_escrow(&self, escrow_id: &Id) -> Result<Option<Escrow>, String> {
        self.get_state(PREFIX_ESCROW, escrow_id)
    }

    pub fn set_escrow(&self, escrow_id: &Id, escrow: &Escrow) -> Result<(), String> {
        self.set_state(PREFIX_ESCROW, escrow_id, escrow)
    }

    // ── Nonce Storage (replay protection) ──

    pub fn get_nonce(&self, sender: &Id) -> u64 {
        let full_key = [PREFIX_NONCE, sender.as_slice()].concat();
        match self.db.get(&full_key) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes[..8].try_into().unwrap())
            }
            _ => 0,
        }
    }

    pub fn set_nonce(&self, sender: &Id, nonce: u64) -> Result<(), String> {
        let full_key = [PREFIX_NONCE, sender.as_slice()].concat();
        self.db
            .put(&full_key, nonce.to_be_bytes())
            .map_err(|e| e.to_string())
    }

    // ── Anchor Storage ──

    pub fn get_anchor(&self, batch_id: &Id) -> Result<Option<AnchorRecord>, String> {
        self.get_state(PREFIX_ANCHOR, batch_id)
    }

    pub fn set_anchor(&self, batch_id: &Id, record: &AnchorRecord) -> Result<(), String> {
        self.set_state(PREFIX_ANCHOR, batch_id, record)
    }

    // ── Dispute Storage ──

    pub fn get_dispute(&self, dispute_id: &Id) -> Result<Option<Dispute>, String> {
        self.get_state(PREFIX_DISPUTE, dispute_id)
    }

    pub fn set_dispute(&self, dispute_id: &Id, dispute: &Dispute) -> Result<(), String> {
        self.set_state(PREFIX_DISPUTE, dispute_id, dispute)
    }

    // ── Atomic Batch Writes ──

    /// Create a new write batch for atomic multi-key operations
    pub fn new_batch(&self) -> StoreBatch {
        StoreBatch {
            batch: WriteBatch::default(),
        }
    }

    /// Commit a batch atomically -- all writes succeed or none do
    pub fn commit_batch(&self, batch: StoreBatch) -> Result<(), String> {
        self.db.write(batch.batch).map_err(|e| e.to_string())
    }

    // ── State Root ──

    /// Compute a deterministic hash over all state entries (Merkle-like state root)
    pub fn compute_state_root(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();

        for prefix in STATE_PREFIXES {
            let iter = self.db.iterator(IteratorMode::From(prefix, rocksdb::Direction::Forward));
            for (key, value) in iter.flatten() {
                if !key.starts_with(prefix) {
                    break;
                }
                hasher.update(&key);
                hasher.update(&value);
            }
        }

        *hasher.finalize().as_bytes()
    }

    // ── Generic State Helpers ──

    fn get_state<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &[u8],
        key: &[u8],
    ) -> Result<Option<T>, String> {
        let full_key = [prefix, key].concat();
        match self.db.get(&full_key).map_err(|e| e.to_string())? {
            Some(bytes) => {
                let value = bincode::deserialize(&bytes).map_err(|e| e.to_string())?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    fn set_state<T: serde::Serialize>(
        &self,
        prefix: &[u8],
        key: &[u8],
        value: &T,
    ) -> Result<(), String> {
        let full_key = [prefix, key].concat();
        let bytes = bincode::serialize(value).map_err(|e| e.to_string())?;
        self.db.put(&full_key, &bytes).map_err(|e| e.to_string())
    }

    fn block_key(height: u64) -> Vec<u8> {
        [PREFIX_BLOCK, &height.to_be_bytes()].concat()
    }
}

/// Atomic write batch -- collects mutations and commits them all-or-nothing
pub struct StoreBatch {
    batch: WriteBatch,
}

impl StoreBatch {
    pub fn set_participant(&mut self, id: &Id, participant: &Participant) {
        self.put_state(PREFIX_PARTICIPANT, id, participant);
    }

    pub fn set_settlement(&mut self, record_id: &Id, record: &SettlementRecord) {
        self.put_state(PREFIX_SETTLEMENT, record_id, record);
    }

    pub fn set_balance(&mut self, owner: &Id, balance: &RCWBalance) {
        self.put_state(PREFIX_BALANCE, owner, balance);
    }

    pub fn set_escrow(&mut self, escrow_id: &Id, escrow: &Escrow) {
        self.put_state(PREFIX_ESCROW, escrow_id, escrow);
    }

    pub fn set_dispute(&mut self, dispute_id: &Id, dispute: &Dispute) {
        self.put_state(PREFIX_DISPUTE, dispute_id, dispute);
    }

    pub fn set_nonce(&mut self, sender: &Id, nonce: u64) {
        let full_key = [PREFIX_NONCE, sender.as_slice()].concat();
        self.batch.put(&full_key, nonce.to_be_bytes());
    }

    fn put_state<T: serde::Serialize>(&mut self, prefix: &[u8], key: &[u8], value: &T) {
        let full_key = [prefix, key].concat();
        // bincode::serialize should not fail for well-formed types
        let bytes = bincode::serialize(value).expect("Serialization must not fail");
        self.batch.put(&full_key, &bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_block_storage() {
        let path = "/tmp/rcw_test_store";
        let _ = fs::remove_dir_all(path);

        let store = Store::open(path).unwrap();

        let block = Block::genesis(1000, [1u8; 32]);
        store.put_block(&block).unwrap();

        let loaded = store.get_block(0).unwrap().unwrap();
        assert_eq!(loaded.header.height, 0);
        assert_eq!(store.get_latest_height(), 0);

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn test_balance_default() {
        let path = "/tmp/rcw_test_balance";
        let _ = fs::remove_dir_all(path);

        let store = Store::open(path).unwrap();
        let id = [42u8; 32];

        let bal = store.get_balance(&id).unwrap();
        assert_eq!(bal.total(), 0);

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn test_store_clone_shares_data() {
        let path = "/tmp/rcw_test_clone";
        let _ = fs::remove_dir_all(path);

        let store1 = Store::open(path).unwrap();
        let store2 = store1.clone();

        let block = Block::genesis(1000, [1u8; 32]);
        store1.put_block(&block).unwrap();

        // store2 sees the same data via Arc<DB>
        let loaded = store2.get_block(0).unwrap().unwrap();
        assert_eq!(loaded.header.height, 0);

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn test_nonce_storage() {
        let path = "/tmp/rcw_test_nonce";
        let _ = fs::remove_dir_all(path);

        let store = Store::open(path).unwrap();
        let sender = [5u8; 32];

        assert_eq!(store.get_nonce(&sender), 0);

        store.set_nonce(&sender, 3).unwrap();
        assert_eq!(store.get_nonce(&sender), 3);

        store.set_nonce(&sender, 10).unwrap();
        assert_eq!(store.get_nonce(&sender), 10);

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn test_batch_atomic_write() {
        let path = "/tmp/rcw_test_batch";
        let _ = fs::remove_dir_all(path);

        let store = Store::open(path).unwrap();
        let id1 = [1u8; 32];
        let id2 = [2u8; 32];

        let mut batch = store.new_batch();
        batch.set_participant(&id1, &Participant {
            id: id1,
            p_type: 1,
            metadata: "p1".to_string(),
            is_active: true,
            ..Default::default()
        });
        batch.set_participant(&id2, &Participant {
            id: id2,
            p_type: 2,
            metadata: "p2".to_string(),
            is_active: true,
            ..Default::default()
        });
        batch.set_nonce(&id1, 5);

        // Before commit, data should not be visible
        assert!(store.get_participant(&id1).unwrap().is_none());

        store.commit_batch(batch).unwrap();

        // After commit, all writes visible atomically
        assert_eq!(store.get_participant(&id1).unwrap().unwrap().metadata, "p1");
        assert_eq!(store.get_participant(&id2).unwrap().unwrap().metadata, "p2");
        assert_eq!(store.get_nonce(&id1), 5);

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn test_state_root_deterministic() {
        let path = "/tmp/rcw_test_state_root";
        let _ = fs::remove_dir_all(path);

        let store = Store::open(path).unwrap();

        // Empty state root
        let root1 = store.compute_state_root();

        // Add a participant
        let id = [1u8; 32];
        let p = Participant {
            id,
            p_type: 1,
            metadata: "test".to_string(),
            is_active: true,
            ..Default::default()
        };
        store.set_participant(&id, &p).unwrap();

        let root2 = store.compute_state_root();
        assert_ne!(root1, root2); // state changed

        // Same state produces same root
        let root3 = store.compute_state_root();
        assert_eq!(root2, root3);

        let _ = fs::remove_dir_all(path);
    }
}
