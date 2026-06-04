#!/usr/bin/env bash
# A1 Phase-5 TWO-INSTANCE determinism proof (#793/#785): boot two independent
# custom-EL instances (A = proposer on 8545/8551, B = verifier on 8555/8561) on
# the SAME canonical genesis (Registry at 0x…0b12), then have A build and B
# verify a settled-only block and a full key+weight+settled block, asserting
# both converge on identical block hashes AND identical 0x…0b12 registry state.
# Builds the EL if needed, boots both, runs the 2-instance drive bin, tears both
# down (no orphaned processes).
#
#   crates/boule-reth/drive-custom-el-2inst.sh
#
# Env: SOLC (genesis gen). Ports 8545/8551 (A) and 8555/8561 (B).
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/../.."
NODE_DIR="$DIR/../boule-reth-node"
DATADIR_A="/tmp/reth-a1-2inst-a"
DATADIR_B="/tmp/reth-a1-2inst-b"
JWT_A="/tmp/reth-a1-2inst-a.jwt"
JWT_B="/tmp/reth-a1-2inst-b.jwt"
EL_REGISTRY="0x0000000000000000000000000000000000000b12"

cleanup() {
  [ -n "${PID_A:-}" ] && kill "$PID_A" 2>/dev/null || true
  [ -n "${PID_B:-}" ] && kill "$PID_B" 2>/dev/null || true
  wait "${PID_A:-}" 2>/dev/null || true
  wait "${PID_B:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

[ -f "$JWT_A" ] || openssl rand -hex 32 > "$JWT_A"
[ -f "$JWT_B" ] || openssl rand -hex 32 > "$JWT_B"
rm -rf "$DATADIR_A" "$DATADIR_B"

# Generate the canonical boule-reth genesis (Registry predeploy at 0x…0b12 with
# the SYSTEM-caller access control). BOTH instances run this same file.
echo "generating canonical genesis (Registry at $EL_REGISTRY)..."
GEN="/tmp/reth-a1-2inst.genesis.json"
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p boule-reth --bin gen-genesis -- 4 "$GEN"
python3 - "$GEN" "$EL_REGISTRY" <<'PY'
import json, sys
gen, el_reg = sys.argv[1], sys.argv[2]
g = json.load(open(gen))
alloc = g["alloc"]
key = next((k for k in alloc if k.lower().endswith("0b12")), None)
assert key is not None, f"no Registry predeploy at {el_reg}"
code = alloc[key].get("code", "")
assert code.startswith("0x60") and len(code) > 2000, "Registry predeploy lacks real code"
print(f"canonical Registry present at {key} ({len(code)} bytes of code)")
PY

EL_BIN="$NODE_DIR/target/debug/boule-reth-node"
if [ ! -x "$EL_BIN" ]; then
  echo "building boule-reth-node (heavy)..."
  : "${BINDGEN_EXTRA_CLANG_ARGS:=-I/usr/lib/gcc/x86_64-linux-gnu/15/include}"
  export BINDGEN_EXTRA_CLANG_ARGS
  (cd "$NODE_DIR" && cargo build --jobs 3)
fi

start_el() {
  local datadir="$1" jwt="$2" authport="$3" httpport="$4" log="$5"
  "$EL_BIN" node \
    --chain "$GEN" \
    --datadir "$datadir" \
    --authrpc.addr 127.0.0.1 --authrpc.port "$authport" --authrpc.jwtsecret "$jwt" \
    --http --http.addr 127.0.0.1 --http.port "$httpport" \
    --http.api "eth,net,web3,txpool,admin" \
    --disable-discovery --ipcdisable --port 0 \
    > "$log" 2>&1 &
  echo $!
}

wait_rpc() {
  local port="$1"
  for _ in $(seq 1 60); do
    if curl -fsS -X POST "http://127.0.0.1:$port" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "EL on :$port did not come up" >&2
  return 1
}

echo "starting instance A (8545/8551)..."
PID_A=$(start_el "$DATADIR_A" "$JWT_A" 8551 8545 /tmp/reth-a1-2inst-a.log)
echo "starting instance B (8555/8561)..."
PID_B=$(start_el "$DATADIR_B" "$JWT_B" 8561 8555 /tmp/reth-a1-2inst-b.log)

echo "waiting for both EL RPCs..."
wait_rpc 8545
wait_rpc 8555

echo "running two-instance determinism drive..."
cargo run -q --manifest-path "$ROOT/Cargo.toml" -p boule-reth --bin drive-custom-el-2inst -- \
  "$JWT_A" "$JWT_B"
