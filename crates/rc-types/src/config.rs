use serde::{Deserialize, Serialize};

/// Node configuration loaded from YAML/JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node: NodeSettings,
    pub consensus: ConsensusSettings,
    pub peers: Vec<PeerConfig>,
    pub rpc: RpcSettings,
    pub rcw: RCWSettings,
    pub dispute: DisputeSettings,
    #[serde(default)]
    pub platform_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeSettings {
    /// Minimum votes required to resolve a dispute
    pub vote_threshold: usize,
}

impl Default for DisputeSettings {
    fn default() -> Self {
        Self { vote_threshold: 3 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSettings {
    pub id: String,
    pub data_path: String,
    pub private_key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusSettings {
    /// Milliseconds between blocks
    pub block_time_ms: u64,
    /// Minimum signatures to finalize (default: 3 of 4)
    pub min_signatures: usize,
    /// P2P listen address for consensus messages
    pub listen_address: String,
    /// View change timeout: if leader fails to produce block within this many ms, next validator takes over
    pub view_change_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub id: String,
    pub address: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcSettings {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RCWSettings {
    pub rewards: RewardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    pub settlement_recorded: u64,
    pub escrow_completed: u64,
    pub trust_90_monthly: u64,
    pub rating_submitted: u64,
    pub dispute_won: u64,
    pub referral: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node: NodeSettings {
                id: "node-1".to_string(),
                data_path: "/var/lib/rcw".to_string(),
                private_key_path: "/etc/rcw/validator.key".to_string(),
            },
            consensus: ConsensusSettings {
                block_time_ms: 1000,
                min_signatures: 3,
                listen_address: "0.0.0.0:26656".to_string(),
                view_change_timeout_ms: 5000,
            },
            peers: Vec::new(),
            rpc: RpcSettings {
                address: "0.0.0.0:26657".to_string(),
            },
            rcw: RCWSettings {
                rewards: RewardConfig {
                    settlement_recorded: 5,
                    escrow_completed: 20,
                    trust_90_monthly: 100,
                    rating_submitted: 2,
                    dispute_won: 50,
                    referral: 50,
                },
            },
            dispute: DisputeSettings::default(),
            platform_keys: Vec::new(),
        }
    }
}
