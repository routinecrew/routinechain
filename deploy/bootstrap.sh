#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/keys"
mkdir -p "$KEYS_DIR"

RCW_BIN="${RCW_BIN:-$SCRIPT_DIR/../target/release/rc-node}"

if [ ! -f "$RCW_BIN" ]; then
    echo "Building rc-node..."
    (cd "$SCRIPT_DIR/.." && ~/.cargo/bin/cargo build --release --bin rc-node)
fi

echo "=== Generating validator keys ==="

for i in 1 2 3; do
    KEY_FILE="$KEYS_DIR/node${i}.key"
    if [ -f "$KEY_FILE" ]; then
        echo "  node${i}: already exists, skipping"
    else
        "$RCW_BIN" keygen --output "$KEY_FILE"
        echo "  node${i}: generated"
    fi
done

PUB1=$(jq -r .public_key "$KEYS_DIR/node1.key")
PUB2=$(jq -r .public_key "$KEYS_DIR/node2.key")
PUB3=$(jq -r .public_key "$KEYS_DIR/node3.key")

echo ""
echo "=== Generating node configs ==="

generate_config() {
    local NODE_NUM=$1
    local NODE_PUB=$2
    local PEER1_NUM=$3
    local PEER1_PUB=$4
    local PEER1_IP=$5
    local PEER2_NUM=$6
    local PEER2_PUB=$7
    local PEER2_IP=$8

    cat > "$SCRIPT_DIR/node${NODE_NUM}.yml" <<EOF
node:
  id: "node-${NODE_NUM}"
  data_path: "/var/lib/rcw"
  private_key_path: "/etc/rcw/validator.key"

consensus:
  block_time_ms: 2000
  min_signatures: 2
  listen_address: "0.0.0.0:26656"
  view_change_timeout_ms: 10000

peers:
  - id: "${PEER1_PUB}"
    address: "${PEER1_IP}:26656"
    public_key: "${PEER1_PUB}"
  - id: "${PEER2_PUB}"
    address: "${PEER2_IP}:26656"
    public_key: "${PEER2_PUB}"

rpc:
  address: "0.0.0.0:26657"

rcw:
  rewards:
    settlement_recorded: 5
    escrow_completed: 20
    trust_90_monthly: 100
    rating_submitted: 2
    dispute_won: 50
    referral: 50

dispute:
  vote_threshold: 3

platform_keys: []
EOF
    echo "  node${NODE_NUM}.yml created"
}

generate_config 1 "$PUB1" 2 "$PUB2" "172.30.0.12" 3 "$PUB3" "172.30.0.13"
generate_config 2 "$PUB2" 1 "$PUB1" "172.30.0.11" 3 "$PUB3" "172.30.0.13"
generate_config 3 "$PUB3" 1 "$PUB1" "172.30.0.11" 2 "$PUB2" "172.30.0.12"

echo ""
echo "=== Bootstrap complete ==="
echo "Node public keys:"
echo "  node1: $PUB1"
echo "  node2: $PUB2"
echo "  node3: $PUB3"
echo ""
echo "To start: docker compose up --build -d"
echo "To add platform key for anchoring: add hex key to platform_keys in node configs"
