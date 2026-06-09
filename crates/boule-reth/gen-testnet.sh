#!/usr/bin/env bash
# Deployment artifact generator for a boule + reth public testnet (#804).
#
# From a single topology spec — N validators + M full nodes, an EVM chain-id,
# and an optional prefund list — this produces a self-contained deployment
# directory: minted keys, a seeded genesis.json (validator weights + chain-id +
# prefund), per-node TOML configs (validator vs full, public + admin listeners,
# static seed peers, reth EL wiring), and run tooling (docker-compose +
# systemd unit templates).
#
# It is the REAL (non-demo) sibling of cluster-el-e2e.sh: same topology
# (validators each driving their own reth EL + non-validating full nodes), but
# the output is durable artifacts an operator deploys, not an ephemeral test.
#
#   crates/boule-reth/gen-testnet.sh                 # N=3 validators, M=1 full
#   N=4 M=2 CHAIN_ID=767676 gen-testnet.sh           # 4 validators, 2 full
#   OUTDIR=/srv/testnet HOST=10.0.0.5 gen-testnet.sh # bind to a real interface
#
# Env knobs:
#   N         validator count                          (default 3)
#   M         full-node count                          (default 1)
#   CHAIN_ID  EVM chain-id seeded into genesis.json     (default 767676)
#   OUTDIR    output directory for all artifacts        (default ./testnet-out)
#   HOST      address the nodes advertise/bind to       (default 127.0.0.1)
#             (use the validators' reachable IP/DNS for a real deployment)
#   PREFUND   space-separated <0xADDR>:<WEI> prefund entries (default: one dev EOA)
#             — a faucet account (#806) is just another entry here.
#   STAKING_OWNER  the address allowed to call Staking.withdraw (#821 — unbonding
#                  removes a validator, a trusted-owner action) (default: dev EOA)
#   GENESIS_STATE_ROOT  pin the genesis EVM state root instead of booting the EL
#                       to read it (skips the throwaway EL boot at generate time).
#
# Requires: cargo (builds boule + the custom EL + the gen-* helpers), and —
# unless GENESIS_STATE_ROOT is set — jq + curl + openssl to read the genesis
# state root once (the consensus↔EL genesis seed) from a throwaway custom EL.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/../.."
NODE_DIR="$DIR/../boule-reth-node"

N="${N:-3}"
M="${M:-1}"
CHAIN_ID="${CHAIN_ID:-767676}"
OUTDIR="${OUTDIR:-$PWD/testnet-out}"
HOST="${HOST:-127.0.0.1}"
# Default prefund: the canonical anvil dev EOA with 1000 ETH (drop/override in
# production). Format: <0xADDR>:<WEI> entries, space-separated.
PREFUND="${PREFUND:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:1000000000000000000000}"
# The address allowed to call the Staking predeploy's `withdraw` (#821):
# unbonding removes a validator, so it is a trusted-owner governance action, not
# open self-service. Defaults to the dev EOA (which is also prefunded above so it
# can pay gas); set STAKING_OWNER to the operator's address in production.
STAKING_OWNER="${STAKING_OWNER:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"
REGISTRY="0x0000000000000000000000000000000000000b12"

SLOTS=$((N + M))
[ "$N" -ge 1 ] || { echo "FATAL: N (validators) must be >= 1"; exit 2; }

# Per-slot ports (0-based). Validators are slots 0..N-1; full nodes N..N+M-1.
authport() { echo $((8551 + 10 * $1)); }   # reth Engine API (auth)
httpport() { echo $((8545 + 10 * $1)); }   # reth eth_* JSON-RPC
elp2p()    { echo $((30330 + $1)); }       # reth p2p
p2pport()  { echo $((7001 + $1)); }        # boule p2p
apiport()  { echo $((8001 + $1)); }        # boule public API
adminport(){ echo $((9001 + $1)); }        # boule admin API (privileged)

BOULE="$ROOT/target/debug/boule"
GEN_TESTNET_GENESIS="$ROOT/target/debug/gen-testnet-genesis"
GEN_BLS="cargo run -q --manifest-path $ROOT/Cargo.toml -p boule-reth --bin gen-bls-genesis --"
EL_BIN="$NODE_DIR/target/debug/boule-reth-node"

echo "── boule testnet generator: $N validators + $M full nodes, chain-id $CHAIN_ID ──"
echo "   OUTDIR=$OUTDIR  HOST=$HOST"

# ── build the binaries we need ──
echo "── building boule (reth feature) + genesis helpers ──"
(cd "$ROOT" && cargo build -q -p boule-cli --features reth --bin boule --jobs 3) \
  || { echo "FATAL: boule build failed"; exit 2; }
(cd "$ROOT" && cargo build -q -p boule-reth --bin gen-testnet-genesis --bin gen-bls-genesis --jobs 3) \
  || { echo "FATAL: genesis-helper build failed"; exit 2; }

rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"/{keys,configs,genesis}
KEYS="$OUTDIR/keys"; CFGS="$OUTDIR/configs"; GEN="$OUTDIR/genesis/genesis.json"

# ── 1. mint a node (Ed25519/TLS) identity per slot; capture its base58 NodeId ──
mint_node() { # slot -> prints NodeId
  local i="$1"
  cat > "$KEYS/init$i.toml" <<EOF
[node]
listen_addr = "$HOST:$(p2pport "$i")"
[node.identity]
backend = "file"
path = "$KEYS/node$i.key"
[api]
listen_addr = "$HOST:$(apiport "$i")"
EOF
  "$BOULE" init --config "$KEYS/init$i.toml" 2>&1 | grep -oP 'NodeId = \K\S+' | head -1
}
echo "── minting $SLOTS node keys ──"
declare -a NID
for i in $(seq 0 $((SLOTS - 1))); do
  NID[$i]=$(mint_node "$i")
  [ -n "${NID[$i]}" ] || { echo "FATAL: node$i key mint failed"; exit 2; }
  role=$( [ "$i" -lt "$N" ] && echo validator || echo full )
  echo "   slot $i ($role): NodeId=${NID[$i]}"
done

# ── 2. mint the validators' BLS keys (PoP seed comes later) ──
# Mint against the all-zeros seed first just to create the key files + read the
# (seed-independent) pubkeys; we re-derive the real PoPs once we have the
# genesis state root. Validators are slots 0..N-1.
echo "── minting $N validator BLS keys ──"
MULTI_ARGS=()
for i in $(seq 0 $((N - 1))); do MULTI_ARGS+=("${NID[$i]}:$KEYS/bls$i.key"); done
ZERO="0000000000000000000000000000000000000000000000000000000000000000"
BLS_PRELOAD=$($GEN_BLS --multi "$ZERO" "${MULTI_ARGS[@]}") \
  || { echo "FATAL: BLS keygen failed"; exit 2; }
declare -a BLS_PUB
for i in $(seq 0 $((N - 1))); do
  BLS_PUB[$i]=$(echo "$BLS_PRELOAD" | grep -oP "^bls_pubkey_$i=\K\S+")
  [ -n "${BLS_PUB[$i]}" ] || { echo "FATAL: no BLS pubkey for validator $i"; exit 2; }
done
chmod 600 "$KEYS"/bls*.key "$KEYS"/node*.key 2>/dev/null || true

# ── 3. weights: 1..=N by default (differ, so the weighted path is exercised) ──
weight() { echo $(( $1 + 1 )); }

# ── 4. build the seeded deployment genesis (chain-id + validator weights + prefund) ──
echo "── building seeded genesis.json (chain-id $CHAIN_ID, $N weighted validators) ──"
VAL_ARGS=()
for i in $(seq 0 $((N - 1))); do
  VAL_ARGS+=(--validator "${NID[$i]}:${BLS_PUB[$i]}:$(weight "$i")")
done
PREFUND_ARGS=()
for p in $PREFUND; do PREFUND_ARGS+=(--prefund "$p"); done
"$GEN_TESTNET_GENESIS" --chain-id "$CHAIN_ID" --staking-owner "$STAKING_OWNER" --out "$GEN" \
  "${PREFUND_ARGS[@]}" "${VAL_ARGS[@]}" \
  || { echo "FATAL: genesis build failed"; exit 2; }
echo "   wrote $GEN"

# ── 5. genesis EVM state root = the consensus↔EL genesis seed ──
# Either pinned via env, or read once from a throwaway custom EL booted on the genesis.
if [ -n "${GENESIS_STATE_ROOT:-}" ]; then
  SEED="${GENESIS_STATE_ROOT#0x}"
  echo "── using pinned genesis state root: $SEED ──"
else
  [ -x "$EL_BIN" ] || { echo "── building boule-reth-node (heavy) to read the genesis root ──"
    : "${BINDGEN_EXTRA_CLANG_ARGS:=-I/usr/lib/gcc/x86_64-linux-gnu/15/include}"
    export BINDGEN_EXTRA_CLANG_ARGS
    (cd "$NODE_DIR" && cargo build --jobs 3) || { echo "FATAL: EL build failed"; exit 2; }; }
  echo "── reading genesis EVM state root from a throwaway custom EL ──"
  TMPRETH="$OUTDIR/.seed-reth"; rm -rf "$TMPRETH"; mkdir -p "$TMPRETH"
  openssl rand -hex 32 > "$TMPRETH/jwt.hex"
  "$EL_BIN" node --chain "$GEN" --datadir "$TMPRETH" \
    --authrpc.addr 127.0.0.1 --authrpc.port 18551 --authrpc.jwtsecret "$TMPRETH/jwt.hex" \
    --http --http.addr 127.0.0.1 --http.port 18545 --http.api eth \
    --disable-discovery --ipcdisable --port 13999 > "$TMPRETH/reth.log" 2>&1 &
  SEED_RETH_PID=$!
  trap '[ -n "${SEED_RETH_PID:-}" ] && kill "$SEED_RETH_PID" 2>/dev/null || true' EXIT
  SEED=""
  for _ in $(seq 1 60); do
    SEED=$(curl -fsS -X POST http://127.0.0.1:18545 -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' \
      2>/dev/null | jq -r '.result.stateRoot // empty' | sed 's/^0x//')
    [ -n "$SEED" ] && break; sleep 1
  done
  kill "$SEED_RETH_PID" 2>/dev/null || true; wait "$SEED_RETH_PID" 2>/dev/null || true
  SEED_RETH_PID=""
  [ -n "$SEED" ] || { echo "FATAL: could not read genesis state root from reth"; exit 2; }
  echo "   genesis state root = $SEED"
fi

# ── 6. re-derive the validators' chain-bound BLS PoPs against the real seed ──
echo "── deriving chain-bound BLS PoPs (seed=$SEED) ──"
BLS_OUT=$($GEN_BLS --multi "$SEED" "${MULTI_ARGS[@]}") \
  || { echo "FATAL: BLS PoP derivation failed"; exit 2; }
declare -a BLS_POP
for i in $(seq 0 $((N - 1))); do
  BLS_PUB[$i]=$(echo "$BLS_OUT" | grep -oP "^bls_pubkey_$i=\K\S+")
  BLS_POP[$i]=$(echo "$BLS_OUT" | grep -oP "^bls_pop_$i=\K\S+")
  [ -n "${BLS_POP[$i]}" ] || { echo "FATAL: no BLS PoP for validator $i"; exit 2; }
done

# ── shared config fragments ──
validators_list() {
  local out="" sep="" i
  for i in $(seq 0 $((N - 1))); do out="$out$sep\"${NID[$i]}\""; sep=", "; done
  echo "$out"
}
validators_bls_block() {
  local i
  for i in $(seq 0 $((N - 1))); do
    cat <<EOF
[[consensus.validators_bls]]
node_id = "${NID[$i]}"
bls_pubkey = "${BLS_PUB[$i]}"
bls_pop = "${BLS_POP[$i]}"
EOF
  done
}
# Static seed peers for slot i: every OTHER slot (a trusted-testnet full mesh).
peers_block() {
  local self="$1" j
  for j in $(seq 0 $((SLOTS - 1))); do
    [ "$j" = "$self" ] && continue
    cat <<EOF
[[peers]]
addr = "$HOST:$(p2pport "$j")"
node_id = "${NID[$j]}"
EOF
  done
}
# reth enode peer list for slot i — placeholder enodes keyed by host+port. A
# reth enode needs the node's secp256k1 pubkey, which reth derives on first
# boot; operators paste the real enodes (admin_nodeInfo) or let reth discover.
# We wire the static p2p port hints so the field is present and documented.
reth_peers_toml() {
  echo ""  # left empty: operators fill in real enode:// URLs post-boot (see runbook)
}

# ── 7. write a node config (validator or full) ──
write_cfg() { # slot
  local i="$1" is_full=0
  [ "$i" -ge "$N" ] && is_full=1
  local cfg="$CFGS/node$i.toml"
  cat > "$cfg" <<EOF
# boule node config — slot $i ($( [ "$is_full" = 1 ] && echo "FULL NODE (non-validating)" || echo "VALIDATOR" ))
# Generated by gen-testnet.sh. Chain-id $CHAIN_ID.
[node]
listen_addr = "$HOST:$(p2pport "$i")"
[node.identity]
backend = "file"
path = "$KEYS/node$i.key"
EOF
  if [ "$is_full" = 0 ]; then
    cat >> "$cfg" <<EOF
[node.bls_validator_identity]
backend = "file"
path = "$KEYS/bls$i.key"
EOF
  fi
  cat >> "$cfg" <<EOF

[api]
# Public, read-only surface (status/peers/metrics/health/ready). Safe to expose.
listen_addr = "$HOST:$(apiport "$i")"
[api.admin]
# Privileged surface (mempool submit, key rotation). Bind to a trusted
# interface; in production set auth_token_env and front with a firewall.
listen_addr = "127.0.0.1:$(adminport "$i")"

$(peers_block "$i")
[consensus]
validators = [$(validators_list)]
full_node = $( [ "$is_full" = 1 ] && echo true || echo false )
signature_scheme = "bls_aggregated"
genesis_seed_hex = "$SEED"
storage_dir = "$OUTDIR/data/consensus$i"
timeout_base_ms = 1000
timeout_max_ms = 8000
min_block_interval_ms = 1000
$(validators_bls_block)
[consensus.application]
backend = "reth"
engine_url = "http://$HOST:$(authport "$i")"
eth_url = "http://$HOST:$(httpport "$i")"
jwt_secret_path = "$OUTDIR/data/jwt$i.hex"
fee_recipient = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
# reth_peers: paste each OTHER node's enode:// URL (admin_nodeInfo) here so the
# ELs gossip txs + self-sync. See docs/join-testnet.md.
reth_peers = [$(reth_peers_toml "$i")]
EOF
  echo "   wrote $cfg"
}
echo "── writing $SLOTS node configs ──"
for i in $(seq 0 $((SLOTS - 1))); do write_cfg "$i"; done

# ── 8. per-node JWT secrets (shared genesis already written) ──
mkdir -p "$OUTDIR/data"
for i in $(seq 0 $((SLOTS - 1))); do
  [ -f "$OUTDIR/data/jwt$i.hex" ] || openssl rand -hex 32 > "$OUTDIR/data/jwt$i.hex" 2>/dev/null \
    || head -c 32 /dev/urandom | xxd -p -c 64 > "$OUTDIR/data/jwt$i.hex"
done

# ── 9. render run tooling (docker-compose + systemd) ──
"$DIR/render-run-tooling.sh" "$OUTDIR" "$N" "$M" "$HOST" \
  || { echo "WARN: run-tooling render failed (configs/genesis still valid)"; }

echo
echo "════════════════════════════════════════════════════════════════"
echo "DONE. Deployment artifacts in: $OUTDIR"
echo "  genesis:  $GEN  (chain-id $CHAIN_ID, $N seeded validators)"
echo "  configs:  $CFGS/node{0..$((SLOTS-1))}.toml  ($N validators + $M full)"
echo "  keys:     $KEYS  (node + BLS keys, mode 0600)"
echo "  seed:     genesis_seed_hex = $SEED"
echo "  run:      $OUTDIR/docker-compose.yml  |  $OUTDIR/systemd/*.service"
echo "  join:     see docs/join-testnet.md to attach a full node"
echo "════════════════════════════════════════════════════════════════"
