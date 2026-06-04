#!/usr/bin/env bash
# Start an execution layer for a boule chain: custom Prague-at-genesis
# chainspec, Engine API on :8551 (JWT), public eth RPC on :8545, no internal
# block production (boule drives it via the Engine API).
#
# Two backends, selected by EL=:
#   EL=stock  (default) — stock `reth` v2.2.0+ on PATH. The tx-write path (#732)
#                         records the Registry via signed system txs.
#   EL=custom           — the A1 custom node `boule-reth-node` (#777/#781), which
#                         applies recordKey/recordWeight/recordSettled as system
#                         calls from the per-block `registryPayload` attribute
#                         (EL-applied writes; no tx). Built from the standalone
#                         `crates/boule-reth-node` workspace. The boule node must
#                         send the custom `registryPayload` build attribute —
#                         see RethEngine::build_block (#781).
#
# Requires reth v2.2.0+ on PATH (v2.2.0 activates Prague — validated). Generates
# jwt.hex and genesis.json on first run.
set -euo pipefail

EL="${EL:-stock}"

DIR="$(cd "$(dirname "$0")" && pwd)"
DATADIR="${DATADIR:-/tmp/reth-boule-data}"
JWT="${JWT:-$DIR/jwt.hex}"

if [ ! -f "$JWT" ]; then
  echo "generating JWT secret at $JWT"
  openssl rand -hex 32 > "$JWT"
fi

# genesis.json is generated (not committed): boule-reth's build.rs compiles the
# predeploy contracts/*.sol with solc into genesis.template.json. Build the
# crate once if the generated file isn't present yet (needs solc — see
# AGENTS.md "Generated artifacts").
if [ ! -f "$DIR/genesis.json" ]; then
  echo "generating genesis.json (compiling predeploy contracts)..."
  (cd "$DIR/../.." && cargo build -p boule-reth >/dev/null)
fi

# Seed the genesis Registry with dev validator weights (#765) so the chain has a
# working weighted-quorum surface (weightOf/totalWeight) from block zero — no
# recordWeight tx. N dev validators (default 4), weights 1..=N. This wraps the
# generated genesis.json (predeploy code) with the per-validator seed words.
N="${N:-4}"
SEEDED="${SEEDED:-$DIR/genesis.seeded.json}"
echo "seeding genesis Registry with $N dev validator weights -> $SEEDED"
(cd "$DIR/../.." && cargo run -q -p boule-reth --bin gen-genesis -- "$N" "$SEEDED")

# Fresh datadir each run keeps the spike reproducible (genesis at height 0).
rm -rf "$DATADIR"

# Pick the EL binary. The custom node is built from its own (excluded) workspace;
# the stock backend is whatever `reth` is on PATH.
if [ "$EL" = "custom" ]; then
  NODE_DIR="$DIR/../boule-reth-node"
  echo "EL=custom: building + running boule-reth-node (the A1 custom EL)"
  # reth's mdbx-sys runs bindgen via libclang with no resource-dir headers on a
  # fresh box; this is the documented host workaround (Cargo.toml / Phase-0).
  : "${BINDGEN_EXTRA_CLANG_ARGS:=-I/usr/lib/gcc/x86_64-linux-gnu/15/include}"
  export BINDGEN_EXTRA_CLANG_ARGS
  (cd "$NODE_DIR" && cargo build --jobs 3 >/dev/null)
  EL_BIN="$NODE_DIR/target/debug/boule-reth-node"
else
  EL_BIN="$(command -v reth)"
fi

exec "$EL_BIN" node \
  --chain "$SEEDED" \
  --datadir "$DATADIR" \
  --authrpc.addr 127.0.0.1 --authrpc.port 8551 --authrpc.jwtsecret "$JWT" \
  --http --http.addr 127.0.0.1 --http.port 8545 \
  --http.api "eth,net,web3,txpool,admin" \
  --disable-discovery \
  --ipcdisable \
  "$@"
