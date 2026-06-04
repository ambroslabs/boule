#!/usr/bin/env bash
# Start reth as a bare execution layer for a boule chain: custom
# Prague-at-genesis chainspec, Engine API on :8551 (JWT), public eth RPC on
# :8545, no internal block production (boule drives it via the Engine API).
#
# Requires reth v2.2.0+ on PATH (v2.2.0 activates Prague — validated). Generates
# jwt.hex and genesis.json on first run.
set -euo pipefail

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

exec reth node \
  --chain "$SEEDED" \
  --datadir "$DATADIR" \
  --authrpc.addr 127.0.0.1 --authrpc.port 8551 --authrpc.jwtsecret "$JWT" \
  --http --http.addr 127.0.0.1 --http.port 8545 \
  --http.api "eth,net,web3,txpool,admin" \
  --disable-discovery \
  --ipcdisable \
  "$@"
