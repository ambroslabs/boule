#!/usr/bin/env bash
# Run a boule + reth node. The chain (genesis, JWT, keys, node.toml) comes from
# CHAIN_DIR; this script only orchestrates the two processes:
#   1. (optional) bootstrap a single-validator chain if CHAIN_DIR has no config
#   2. start the execution layer
#   3. wait for its RPC (boule queries the EL at startup and does NOT retry)
#   4. exec boule with the provided config
#
# Everything chain-specific lives in CHAIN_DIR, so the same image runs a
# validator, a full node, or one-of-N in a cluster — just mount that node's
# artifacts. Env knobs (with Dockerfile defaults): CHAIN_DIR, DATA_DIR,
# EL_HTTP_ADDR/PORT, EL_AUTHRPC_PORT, EL_P2P_PORT, RETH_EXTRA_ARGS, BOOTSTRAP.
set -euo pipefail

: "${CHAIN_DIR:=/chain}"
: "${DATA_DIR:=/data}"
: "${GENESIS:=$CHAIN_DIR/genesis.json}"
: "${JWT:=$CHAIN_DIR/jwt.hex}"
: "${BOULE_CONFIG:=$CHAIN_DIR/node.toml}"
: "${EL_HTTP_ADDR:=0.0.0.0}"
: "${EL_HTTP_PORT:=8545}"
: "${EL_AUTHRPC_PORT:=8551}"
: "${EL_P2P_PORT:=30303}"
: "${RETH_EXTRA_ARGS:=}"
: "${BOOTSTRAP:=auto}"

# 1. Bootstrap the zero-config single-validator default when nothing is mounted.
if [ ! -f "$BOULE_CONFIG" ]; then
  if [ "$BOOTSTRAP" = auto ]; then
    echo "no config at $BOULE_CONFIG — bootstrapping a single-validator chain into $CHAIN_DIR"
    bootstrap-single-validator.sh
  else
    echo "FATAL: no config at $BOULE_CONFIG and BOOTSTRAP=$BOOTSTRAP (mount a chain into $CHAIN_DIR)" >&2
    exit 1
  fi
fi

# 2. Start the execution layer. authrpc stays on loopback (only the co-located
#    boule node drives it); the eth RPC and p2p port bind outward.
boule-reth-node node \
  --chain "$GENESIS" --datadir "$DATA_DIR/reth" \
  --authrpc.addr 127.0.0.1 --authrpc.port "$EL_AUTHRPC_PORT" --authrpc.jwtsecret "$JWT" \
  --http --http.addr "$EL_HTTP_ADDR" --http.port "$EL_HTTP_PORT" \
  --http.api eth,net,web3,txpool,admin \
  --port "$EL_P2P_PORT" --disable-discovery --ipcdisable $RETH_EXTRA_ARGS &
EL_PID=$!

# 3. Wait for the EL RPC (it boots in a few seconds; boule won't retry).
echo "waiting for execution layer RPC on :$EL_HTTP_PORT…"
until curl -fsS -X POST "http://127.0.0.1:$EL_HTTP_PORT" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' >/dev/null 2>&1; do
  kill -0 "$EL_PID" 2>/dev/null || { echo "FATAL: execution layer exited before becoming ready" >&2; exit 1; }
  sleep 0.5
done

# 4. Hand off to boule. exec → boule becomes PID 1 and receives signals directly;
#    the EL is reparented and torn down with the container (use `docker run
#    --init` for a tini reaper if you want the EL reaped on boule exit).
echo "execution layer up; starting boule ($BOULE_CONFIG)"
exec boule start -c "$BOULE_CONFIG"
