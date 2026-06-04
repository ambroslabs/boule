#!/usr/bin/env bash
# A1 Phase-1 live proof (#781): drive the custom EL (boule-reth-node) with a
# `registryPayload` build attribute produced by boule's PRODUCTION population
# code, then read the Registry back and assert keyAt/weightOf/settledView reflect
# the passed write set. Builds the EL if needed, boots it, runs the drive bin,
# and tears the EL down (no orphaned processes).
#
#   crates/boule-reth/drive-custom-el.sh
#
# Env: SOLC (for genesis gen). Uses ports 8545/8551, datadir /tmp/reth-a1-drive.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/../.."
NODE_DIR="$DIR/../boule-reth-node"
DATADIR="/tmp/reth-a1-drive"
JWT="/tmp/reth-a1-drive.jwt"
# The canonical Registry predeploy address (#793): the custom EL writes here
# (boule_reth_node::registry::REGISTRY_ADDRESS) AND boule's generated genesis
# already seeds the Registry here (boule_reth::registry::REGISTRY_ADDRESS), so
# the EL's system calls hit the same contract slashing/governance/keyAt/weightOf
# /settledView read. No mirroring to a second address — 0x…0b12 is the one truth.
EL_REGISTRY="0x0000000000000000000000000000000000000b12"

cleanup() {
  [ -n "${EL_PID:-}" ] && kill "$EL_PID" 2>/dev/null || true
  wait "${EL_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# JWT + datadir.
[ -f "$JWT" ] || openssl rand -hex 32 > "$JWT"
rm -rf "$DATADIR"

# Generate the boule-reth genesis (predeploy code + dev validator seed). It
# already seeds the canonical Registry at 0x…0b12 with the SYSTEM-caller access
# control (#788), which is exactly the address the custom EL writes to (#793) —
# so we run that genesis verbatim, no mirroring to a second address. Assert the
# Registry predeploy is present at the canonical address before booting.
echo "generating drive genesis (canonical Registry at $EL_REGISTRY)..."
GEN="/tmp/reth-a1-drive.genesis.json"
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p boule-reth --bin gen-genesis -- 4 "$GEN"
python3 - "$GEN" "$EL_REGISTRY" <<'PY'
import json, sys
gen, el_reg = sys.argv[1], sys.argv[2]
g = json.load(open(gen))
alloc = g["alloc"]
# The canonical Registry predeploy must be seeded at 0x…0b12 with code, or the
# EL's system calls would hit a dead address (#793).
key = next((k for k in alloc if k.lower().endswith("0b12")), None)
assert key is not None, f"no Registry predeploy at {el_reg} in generated genesis"
code = alloc[key].get("code", "")
assert code.startswith("0x60") and len(code) > 2000, "Registry predeploy lacks real code"
print(f"canonical Registry present at {key} ({len(code)} bytes of code)")
PY

# Build the custom EL if not present.
EL_BIN="$NODE_DIR/target/debug/boule-reth-node"
if [ ! -x "$EL_BIN" ]; then
  echo "building boule-reth-node (heavy)..."
  : "${BINDGEN_EXTRA_CLANG_ARGS:=-I/usr/lib/gcc/x86_64-linux-gnu/15/include}"
  export BINDGEN_EXTRA_CLANG_ARGS
  (cd "$NODE_DIR" && cargo build --jobs 3)
fi

echo "starting custom EL..."
"$EL_BIN" node \
  --chain "$GEN" \
  --datadir "$DATADIR" \
  --authrpc.addr 127.0.0.1 --authrpc.port 8551 --authrpc.jwtsecret "$JWT" \
  --http --http.addr 127.0.0.1 --http.port 8545 \
  --http.api "eth,net,web3,txpool,admin" \
  --disable-discovery --ipcdisable \
  > /tmp/reth-a1-drive.log 2>&1 &
EL_PID=$!

# Wait for the public RPC to answer.
echo "waiting for EL RPC on :8545..."
for _ in $(seq 1 60); do
  if curl -fsS -X POST http://127.0.0.1:8545 \
      -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "driving the EL with boule's production registry population..."
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p boule-reth --bin drive-custom-el -- "$JWT"
