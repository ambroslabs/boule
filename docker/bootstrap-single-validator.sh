#!/usr/bin/env bash
# Generate a self-contained single-validator chain into CHAIN_DIR — the
# zero-config default the entrypoint runs when nothing is mounted. Writes:
#   genesis.json  predeploys + 1 dev validator weight (gen-genesis)
#   jwt.hex       Engine API CL<->EL shared secret
#   node.key      boule network/consensus identity (boule init)
#   bls.key       BLS validator-signing key (gen-bls-genesis)
#   node.toml     boule config wiring consensus to the local reth EL
#
# For any real/multi-node chain, mount prebuilt artifacts into CHAIN_DIR instead
# (e.g. from crates/boule-reth/gen-testnet.sh) and this never runs.
set -euo pipefail

: "${CHAIN_DIR:=/chain}"
: "${DATA_DIR:=/data}"
: "${EL_AUTHRPC_PORT:=8551}"
: "${EL_HTTP_PORT:=8545}"

mkdir -p "$CHAIN_DIR"

# 1. Genesis + the Engine API JWT secret.
gen-genesis 1 "$CHAIN_DIR/genesis.json"
openssl rand -hex 32 > "$CHAIN_DIR/jwt.hex"

# 2. Read the genesis EVM state root from a throwaway EL boot. The consensus
#    genesis must equal it (genesis_seed_hex) and the BLS PoP binds to it.
boule-reth-node node --chain "$CHAIN_DIR/genesis.json" --datadir /tmp/seed-reth \
  --authrpc.addr 127.0.0.1 --authrpc.port "$EL_AUTHRPC_PORT" --authrpc.jwtsecret "$CHAIN_DIR/jwt.hex" \
  --http --http.addr 127.0.0.1 --http.port "$EL_HTTP_PORT" --http.api eth \
  --disable-discovery --ipcdisable >/tmp/seed-reth.log 2>&1 &
EL_PID=$!
# Stop the throwaway EL on any exit so it never lingers / clashes with the real one.
trap 'kill "$EL_PID" 2>/dev/null || true; wait "$EL_PID" 2>/dev/null || true' EXIT

SEED=""
for _ in $(seq 1 90); do
  # `|| true`: a connection-refused while the EL warms up must not trip `set -e`.
  SEED=$(curl -fsS -X POST "http://127.0.0.1:$EL_HTTP_PORT" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' \
    2>/dev/null | jq -r '.result.stateRoot // empty' 2>/dev/null | sed 's/^0x//' || true)
  [ -n "$SEED" ] && break
  kill -0 "$EL_PID" 2>/dev/null || { echo "FATAL: EL exited during bootstrap"; cat /tmp/seed-reth.log; exit 1; }
  sleep 1
done
[ -n "$SEED" ] || { echo "FATAL: could not read genesis state root"; cat /tmp/seed-reth.log; exit 1; }
echo "genesis state root = $SEED"

# 3. Provision the node identity key (boule init mints node.key and prints the
#    NodeId) from a minimal gossip-only config.
cat > "$CHAIN_DIR/init.toml" <<EOF
[node]
listen_addr = "0.0.0.0:7000"
[node.identity]
backend = "file"
path    = "$CHAIN_DIR/node.key"
[api]
listen_addr = "0.0.0.0:8000"
EOF
ID=$(boule init -c "$CHAIN_DIR/init.toml" | grep -oP 'NodeId = \K\S+' | head -1)
[ -n "$ID" ] || { echo "FATAL: boule init printed no NodeId"; exit 1; }
echo "validator NodeId = $ID"

# 4. Mint the BLS key + genesis-bound proof-of-possession (seed = EL state root).
BLS=$(gen-bls-genesis "$ID" "$CHAIN_DIR/bls.key" "$SEED")
PUB=$(printf '%s\n' "$BLS" | sed -n 's/^bls_pubkey=//p')
POP=$(printf '%s\n' "$BLS" | sed -n 's/^bls_pop=//p')
[ -n "$PUB" ] && [ -n "$POP" ] || { echo "FATAL: gen-bls-genesis output unparsable"; exit 1; }

# 5. Write the node config: committee = this one validator, EL backend = the
#    co-located reth on loopback.
cat > "$CHAIN_DIR/node.toml" <<EOF
[node]
listen_addr = "0.0.0.0:7000"
[node.identity]
backend = "file"
path    = "$CHAIN_DIR/node.key"
[node.bls_validator_identity]
backend = "file"
path    = "$CHAIN_DIR/bls.key"
[api]
listen_addr = "0.0.0.0:8000"

[consensus]
validators            = ["$ID"]
genesis_seed_hex      = "$SEED"
storage_dir           = "$DATA_DIR/consensus"
min_block_interval_ms = 1000

[[consensus.validators_bls]]
node_id    = "$ID"
bls_pubkey = "$PUB"
bls_pop    = "$POP"

[consensus.application]
backend         = "reth"
engine_url      = "http://127.0.0.1:$EL_AUTHRPC_PORT"
eth_url         = "http://127.0.0.1:$EL_HTTP_PORT"
jwt_secret_path = "$CHAIN_DIR/jwt.hex"
fee_recipient   = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
EOF

rm -f "$CHAIN_DIR/init.toml"
echo "bootstrapped single-validator chain into $CHAIN_DIR"
