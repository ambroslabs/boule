#!/usr/bin/env bash
# Single-validator smoke for the bundled boule node (#884/#885/#886):
# one process = boule consensus + the custom reth EL in-process (no second
# process, no HTTP Engine API, no JWT). Asserts blocks COMMIT via eth_blockNumber.
#
# The bundle crate is CI-excluded (heavy reth tree), so this is the local
# verification gate. Build prerequisites first:
#   export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/15/include"
#   (cd crates/boule-bundle && cargo build --jobs 3)         # the `boule node` binary
#   cargo build -p boule-cli -p boule-reth \
#     --bin boule --bin gen-genesis --bin gen-bls-genesis    # init + genesis helpers
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"            # crates/boule-bundle
ROOT="$(cd "$DIR/../.." && pwd)"                 # repo root
BUNDLE="$DIR/target/debug/boule"                # the bundled `boule node` binary
CLI="$ROOT/target/debug/boule"                  # boule-cli (init/keys)
GEN_GENESIS="$ROOT/target/debug/gen-genesis"
GEN_BLS="$ROOT/target/debug/gen-bls-genesis"

WORK="${WORK:-/tmp/boule-bundle-smoke}"
DATADIR="$WORK/reth"
ETH=http://127.0.0.1:8545
LOG="$WORK/boule.log"
IPC="$WORK/engine.ipc"

BOULE_PID=""
cleanup() {
  echo "── tearing down ──"
  [ -n "$BOULE_PID" ] && kill "$BOULE_PID" 2>/dev/null || true
  wait "$BOULE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

rm -rf "$WORK"; mkdir -p "$WORK"

echo "── generating seeded genesis (Registry + dev validator weights) ──"
GEN="$WORK/genesis.json"
"$GEN_GENESIS" 4 "$GEN"

echo "── starting throwaway reth-free key mint via boule-cli init ──"
cat > "$WORK/init.toml" <<EOF
[node]
listen_addr = "127.0.0.1:7000"
[node.identity]
backend = "file"
path = "$WORK/node.key"
[api]
listen_addr = "127.0.0.1:8000"
EOF
NID=$("$CLI" init --config "$WORK/init.toml" 2>&1 | grep -oP 'NodeId = \K\S+' | head -1)
[ -n "$NID" ] || { echo "FATAL: no NodeId"; exit 2; }
echo "   NodeId = $NID"

# We need the EL genesis state root as the consensus genesis seed. Read it from
# the genesis file's stateRoot is not present (alloc-only) — so boot reth once is
# the canonical source; but gen-genesis's state root is deterministic. Easiest:
# start the node WITHOUT a seed first to read reth's root from the bridge error,
# OR compute it. We boot a short-lived reth via the bundle with a deliberately
# wrong seed to capture the fail-closed error that prints the correct root.
echo "── discovering reth genesis state root (fail-closed bridge prints it) ──"
cat > "$WORK/probe.toml" <<EOF
[node]
listen_addr = "127.0.0.1:7000"
[node.identity]
backend = "file"
path = "$WORK/node.key"
[api]
listen_addr = "127.0.0.1:8000"
[consensus]
validators = ["$NID"]
genesis_seed_hex = "0000000000000000000000000000000000000000000000000000000000000000"
storage_dir = "$WORK/consensus-probe"
[consensus.application]
backend = "reth-inprocess"
fee_recipient = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
EOF
chmod 600 "$WORK/node.key" 2>/dev/null || true
SEED=$("$BUNDLE" node -c "$WORK/probe.toml" --chain "$GEN" --datadir "$WORK/reth-probe" \
  --authrpc.ipcpath "$WORK/probe.ipc" --http.port 8600 --authrpc.port 8651 \
  2>&1 | grep -oP 'genesis state root \K[0-9a-f]{64}' | head -1)
echo "   reth genesis state root = $SEED"
[ -n "$SEED" ] || { echo "FATAL: could not read reth genesis root"; exit 2; }

echo "── minting BLS key + chain-bound PoP (seed=$SEED) ──"
BLS_OUT=$("$GEN_BLS" "$NID" "$WORK/bls.key" "$SEED")
BLS_PUB=$(echo "$BLS_OUT" | grep -oP 'bls_pubkey=\K\S+')
BLS_POP=$(echo "$BLS_OUT" | grep -oP 'bls_pop=\K\S+')
[ -n "$BLS_PUB" ] && [ -n "$BLS_POP" ] || { echo "FATAL: BLS gen failed: $BLS_OUT"; exit 2; }
chmod 600 "$WORK/bls.key" 2>/dev/null || true
echo "   bls_pubkey = ${BLS_PUB:0:24}…"

cat > "$WORK/node.toml" <<EOF
[node]
listen_addr = "127.0.0.1:7000"
[node.identity]
backend = "file"
path = "$WORK/node.key"
[node.bls_validator_identity]
backend = "file"
path = "$WORK/bls.key"
[api]
listen_addr = "127.0.0.1:8000"
[consensus]
validators = ["$NID"]
signature_scheme = "bls_aggregated"
genesis_seed_hex = "$SEED"
storage_dir = "$WORK/consensus"
timeout_base_ms = 500
timeout_max_ms = 5000
min_block_interval_ms = 800
[[consensus.validators_bls]]
node_id = "$NID"
bls_pubkey = "$BLS_PUB"
bls_pop = "$BLS_POP"
[consensus.application]
backend = "reth-inprocess"
fee_recipient = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
EOF

echo "── starting bundled boule node (ONE process: consensus + reth in-process) ──"
RUST_LOG=info "$BUNDLE" node -c "$WORK/node.toml" --chain "$GEN" --datadir "$DATADIR" \
  --authrpc.ipcpath "$IPC" --http.port 8545 --authrpc.port 8551 \
  > "$LOG" 2>&1 &
BOULE_PID=$!

el_head() {
  curl -fsS -X POST "$ETH" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null \
    | grep -oP '"result":"0x\K[0-9a-f]+' | head -1
}

echo "── waiting for the single-process chain to commit blocks ──"
STARTED=0; LAST=0
for _ in $(seq 1 90); do
  if ! kill -0 "$BOULE_PID" 2>/dev/null; then
    echo "FATAL: bundled node exited early"; echo "--- log tail ---"; tail -60 "$LOG"; exit 2
  fi
  hex=$(el_head); hex=${hex:-0}
  if [ -n "$hex" ]; then dec=$((16#$hex)); else dec=0; fi
  echo "   eth_blockNumber = 0x$hex ($dec)"
  LAST=$dec
  [ "$dec" -ge 5 ] && { STARTED=1; break; }
  sleep 2
done

echo
if [ "$STARTED" = 1 ]; then
  echo "RESULT: PASS — single-process boule+reth committed blocks; eth_blockNumber reached $LAST."
  exit 0
else
  echo "RESULT: FAIL — chain did not advance past several blocks (last=$LAST)."
  echo "--- log tail ---"; tail -80 "$LOG"
  exit 1
fi
