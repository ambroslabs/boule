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
# The custom EL writes the Registry at this address (mirror of
# boule_reth_node::registry::REGISTRY_ADDRESS). The drive genesis must deploy the
# Registry code here so the EL's system calls hit real contract code.
EL_REGISTRY="0x00000000000000000000000000000000000b0011"

cleanup() {
  [ -n "${EL_PID:-}" ] && kill "$EL_PID" 2>/dev/null || true
  wait "${EL_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# JWT + datadir.
[ -f "$JWT" ] || openssl rand -hex 32 > "$JWT"
rm -rf "$DATADIR"

# Build the boule-reth genesis (predeploy code + dev validator seed), then COPY
# the Registry alloc entry (code + storage) to the EL's write address so the
# custom executor's system calls land on real contract code. (The b0011 vs 0b12
# address split between #788's node and boule-reth's genesis is a known seam to
# reconcile — see the PR; here we deploy at both so the live proof can read back.)
echo "generating drive genesis (Registry mirrored at $EL_REGISTRY)..."
GEN="/tmp/reth-a1-drive.genesis.json"
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p boule-reth --bin gen-genesis -- 4 "$GEN.base"
python3 - "$GEN.base" "$GEN" "$EL_REGISTRY" <<'PY'
import json, sys
base, out, el_reg = sys.argv[1], sys.argv[2], sys.argv[3]
g = json.load(open(base))
alloc = g["alloc"]
# Find the boule-reth Registry entry (lowercase 0b12) case-insensitively.
src_key = next(k for k in alloc if k.lower().endswith("0b12"))
reg = json.loads(json.dumps(alloc[src_key]))  # deep copy (code + storage)
alloc[el_reg] = reg
json.dump(g, open(out, "w"), indent=2)
print(f"mirrored Registry {src_key} -> {el_reg}")
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
