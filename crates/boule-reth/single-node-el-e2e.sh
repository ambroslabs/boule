#!/usr/bin/env bash
# A1 Phase-5 single-node REAL boule↔EL e2e (#785/#777, the Phase-3 gate).
#
# Stands up ONE real boule validator (the sole proposer) on a BLS chain driving
# the custom EL (boule-reth-node) over the Engine API, then exercises a BLS-key
# rotation and a stake/weight change THROUGH REAL CONSENSUS — not the
# drive-custom-el harness — and asserts the Registry at 0x…0b12 reflects, written
# by the EL from the per-block registryPayload attribute:
#
#   1. keyAt(validator, v_eff) returns the rotated 128-byte BLS key,
#   2. weightOf(validator)     reflects the deposited stake change,
#   3. settledView()           advances as views commit.
#
# Why a BLS chain: only a BLS-bearing rotation carries a new BLS pubkey, which is
# the only thing recordKey writes (`record_key_for_rotation` → None on Ed25519).
#
# The rotation's v_eff is set FAR in the future, so the sole validator never has
# to swap its live signing key (the offline `rotation propose` path does not
# register a hot-swap) — yet recordKey is applied by the EL when the rotation
# COMMITS (it rides that block's registryPayload), so keyAt(validator, v_eff)
# returns the new key well before v_eff would take effect. The chain keeps
# committing under the genesis key throughout.
#
#   crates/boule-reth/single-node-el-e2e.sh
#
# Env: SOLC (genesis gen). Ports: EL 8545/8551, boule p2p 7000, api 8000.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/../.."
NODE_DIR="$DIR/../boule-reth-node"
WORK="${WORK:-/tmp/boule-el-e2e}"
DATADIR="$WORK/reth"
JWT="$WORK/jwt.hex"
EL_LOG="$WORK/el.log"
BOULE_LOG="$WORK/boule.log"
REGISTRY="0x0000000000000000000000000000000000000b12"
STAKING="0x0000000000000000000000000000000000000b0e"
ETH=http://127.0.0.1:8545
API=http://127.0.0.1:8000
SENDER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

BOULE="${BOULE:-$ROOT/target/debug/boule}"
CARGO_RUN="cargo run -q --manifest-path $ROOT/Cargo.toml"

EL_PID=""; BOULE_PID=""
cleanup() {
  echo "── tearing down ──"
  [ -n "$BOULE_PID" ] && kill "$BOULE_PID" 2>/dev/null || true
  [ -n "$EL_PID" ] && kill "$EL_PID" 2>/dev/null || true
  wait "$BOULE_PID" 2>/dev/null || true
  wait "$EL_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for bin in reth openssl jq curl python3 xxd; do
  command -v "$bin" >/dev/null || { echo "FATAL: '$bin' not on PATH"; exit 2; }
done

# RPC helper (replaces foundry's `cast`, which is not on this box). Build once.
echo "── building el-e2e-ops RPC helper ──"
$CARGO_RUN -p boule-reth --bin el-e2e-ops -- --help >/dev/null 2>&1 || true
OPS="$ROOT/target/debug/el-e2e-ops"
(cd "$ROOT" && cargo build -q -p boule-reth --bin el-e2e-ops --jobs 3)

rm -rf "$WORK"; mkdir -p "$WORK"
openssl rand -hex 32 > "$JWT"

echo "── generating canonical genesis (Registry at $REGISTRY) ──"
GEN="$WORK/genesis.json"
$CARGO_RUN -p boule-reth --bin gen-genesis -- 4 "$GEN"

EL_BIN="$NODE_DIR/target/debug/boule-reth-node"
if [ ! -x "$EL_BIN" ]; then
  echo "── building boule-reth-node (heavy) ──"
  : "${BINDGEN_EXTRA_CLANG_ARGS:=-I/usr/lib/gcc/x86_64-linux-gnu/15/include}"
  export BINDGEN_EXTRA_CLANG_ARGS
  (cd "$NODE_DIR" && cargo build --jobs 3)
fi
[ -x "$BOULE" ] || { echo "── building boule (reth feature) ──"; (cd "$ROOT" && cargo build -p boule-cli --features reth --jobs 3); }

echo "── starting custom EL (boule-reth-node) ──"
"$EL_BIN" node \
  --chain "$GEN" --datadir "$DATADIR" \
  --authrpc.addr 127.0.0.1 --authrpc.port 8551 --authrpc.jwtsecret "$JWT" \
  --http --http.addr 127.0.0.1 --http.port 8545 \
  --http.api "eth,net,web3,txpool,admin" \
  --disable-discovery --ipcdisable \
  > "$EL_LOG" 2>&1 &
EL_PID=$!

echo "── waiting for EL RPC ──"
for _ in $(seq 1 60); do
  curl -fsS -X POST "$ETH" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' >/dev/null 2>&1 && break
  sleep 1
done
SEED=$(curl -fsS -X POST "$ETH" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' \
  | jq -r '.result.stateRoot'); SEED=${SEED#0x}
echo "   EL genesis state root (genesis_seed_hex) = $SEED"

# ── mint the node key, read NodeId ──
echo "── minting boule node key ──"
cat > "$WORK/init.toml" <<EOF
[node]
listen_addr = "127.0.0.1:7000"
[node.identity]
backend = "file"
path = "$WORK/node.key"
[api]
listen_addr = "127.0.0.1:8000"
EOF
NID=$("$BOULE" init --config "$WORK/init.toml" 2>&1 | grep -oP 'NodeId = \K\S+' | head -1)
[ -n "$NID" ] || { echo "FATAL: no NodeId"; exit 2; }
echo "   NodeId = $NID"

b58_to_hex() {
  python3 - "$1" <<'PY'
import sys
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = 0
for c in sys.argv[1]:
    n = n * 58 + A.index(c)
print("0x" + n.to_bytes(32, "big").hex())
PY
}
NID_HEX=$(b58_to_hex "$NID")
echo "   NodeId (bytes32) = $NID_HEX"

# ── mint the BLS key + chain-bound PoP for the reth-seeded genesis ──
echo "── minting BLS key + chain-bound PoP (seed=$SEED) ──"
BLS_OUT=$($CARGO_RUN -p boule-reth --bin gen-bls-genesis -- "$NID" "$WORK/bls.key" "$SEED")
BLS_PUB=$(echo "$BLS_OUT" | grep -oP 'bls_pubkey=\K\S+')
BLS_POP=$(echo "$BLS_OUT" | grep -oP 'bls_pop=\K\S+')
[ -n "$BLS_PUB" ] && [ -n "$BLS_POP" ] || { echo "FATAL: BLS genesis gen failed: $BLS_OUT"; exit 2; }
echo "   bls_pubkey = ${BLS_PUB:0:24}…  bls_pop = ${BLS_POP:0:24}…"

# ── full BLS node config (single validator = sole proposer) ──
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
backend = "reth"
engine_url = "http://127.0.0.1:8551"
eth_url = "$ETH"
jwt_secret_path = "$JWT"
fee_recipient = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
EOF

# Need allow-insecure-perms on the BLS key file (the e2e wrote it group-readable
# under /tmp). Tighten it instead so the node accepts it.
chmod 600 "$WORK/bls.key" "$WORK/node.key" 2>/dev/null || true

echo "── starting boule validator (sole proposer, custom EL backend, BLS) ──"
"$BOULE" start --config "$WORK/node.toml" > "$BOULE_LOG" 2>&1 &
BOULE_PID=$!

el_head() { "$OPS" block-number 2>/dev/null || echo 0; }
# read all registry fields at once: sets WEIGHTOF/TOTALWEIGHT/HISTORYLENGTH/SETTLEDVIEW/KEYATLEN
reg_read() {
  local id="$1" veff="$2" line
  WEIGHTOF=0; TOTALWEIGHT=0; HISTORYLENGTH=0; SETTLEDVIEW=0; KEYATLEN=0
  while IFS='=' read -r k v; do
    case "$k" in
      weightOf) WEIGHTOF=$v;; totalWeight) TOTALWEIGHT=$v;;
      historyLength) HISTORYLENGTH=$v;; settledView) SETTLEDVIEW=$v;;
      keyAtLen) KEYATLEN=$v;;
    esac
  done < <("$OPS" read "$id" "$veff" 2>/dev/null)
}
node_view() {
  curl -fsS "$API/consensus/status" 2>/dev/null \
    | jq -r '(.current_view // .view // 0) | if type=="object" then .[] else . end' 2>/dev/null || echo 0
}

echo "── waiting for the chain to start committing blocks ──"
STARTED=0
for _ in $(seq 1 60); do
  h=$(el_head); v=$(node_view); echo "   EL head=$h node_view=$v"
  [ "$h" -ge 3 ] && { STARTED=1; break; }
  sleep 2
done
[ "$STARTED" = 1 ] || { echo "FATAL: chain never advanced"; echo "--- boule log ---"; tail -50 "$BOULE_LOG"; echo "--- EL log ---"; tail -20 "$EL_LOG"; exit 2; }

FAILS=0
fail() { echo "  ✗ $1"; FAILS=$((FAILS + 1)); }
pass() { echo "  ✓ $1"; }

echo
echo "════════════════ EXERCISING REGISTRY WRITES (EL-applied) ════════════════"

# ── (A) stake/weight change: deposit against MY validator's NodeId ──
echo "── (A) depositing stake for $NID (weight change) ──"
reg_read "$NID_HEX" 0
W_BEFORE=$WEIGHTOF; TW_BEFORE=$TOTALWEIGHT
echo "   weightOf(before)=$W_BEFORE  totalWeight(before)=$TW_BEFORE"
DEPOSIT_WEI=750000
TXH=$("$OPS" deposit "$NID_HEX" "$DEPOSIT_WEI" 2>"$WORK/dep.err")
if [ -z "$TXH" ]; then fail "deposit: el-e2e-ops deposit failed: $(cat "$WORK/dep.err")"; else echo "   deposit tx = $TXH"; fi

# ── (B) BLS-key rotation, far-future v_eff (chain never has to swap live) ──
CUR_VIEW=$(node_view); CUR_VIEW=${CUR_VIEW:-0}
ROT_VEFF=$(( CUR_VIEW + 100000 ))
echo "── (B) building a BLS rotation (v_eff=$ROT_VEFF, far future) ──"
# `boule` writes tracing to stdout alongside the println'd hex; silence logs and
# keep only the single pure-hex line (the envelope).
RUST_LOG=off "$BOULE" rotation propose -c "$WORK/node.toml" \
  --new-key-backend file --new-key-path "$WORK/node.key.new" \
  --new-bls-key-backend file --new-bls-key-path "$WORK/bls.key.new" \
  --v-eff "$ROT_VEFF" >"$WORK/rot.out" 2>"$WORK/rot.err"
echo "   (rot.out wrote $(wc -c < "$WORK/rot.out") bytes)"
# Extract the first long pure-hex token (the envelope) from stdout.
ROT_HEX=$(grep -oiE '[0-9a-f]{64,}' "$WORK/rot.out" | head -1)
echo "   (extracted ROT_HEX length=${#ROT_HEX})"
echo "   rotation envelope: ${ROT_HEX:0:32}… ($(( ${#ROT_HEX} / 2 )) bytes)"
cat "$WORK/rot.err"
if [ -z "$ROT_HEX" ]; then
  fail "rotation: rotation propose produced no envelope"
else
  echo "$ROT_HEX" | xxd -r -p > "$WORK/rot.bin"
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/mempool/submit" \
    -H 'content-type: application/octet-stream' --data-binary @"$WORK/rot.bin")
  echo "   /mempool/submit -> HTTP $CODE"
  [ "$CODE" = 202 ] || [ "$CODE" = 200 ] || fail "rotation: mempool submit returned HTTP $CODE"
fi

echo
echo "── letting blocks commit so the EL applies the registry writes ──"
for _ in $(seq 1 60); do
  h=$(el_head); reg_read "$NID_HEX" "$ROT_VEFF"
  echo "   EL head=$h settledView=$SETTLEDVIEW historyLength=$HISTORYLENGTH weightOf=$WEIGHTOF keyAtLen=$KEYATLEN"
  { [ "$HISTORYLENGTH" -ge 1 ] && [ "$WEIGHTOF" -gt 0 ] && [ "$SETTLEDVIEW" -gt 0 ] && [ "$KEYATLEN" = 128 ]; } && break
  sleep 2
done

echo
echo "════════════════════════ ASSERTIONS (read-back) ════════════════════════"

reg_read "$NID_HEX" "$ROT_VEFF"
W_AFTER=$WEIGHTOF; TW_AFTER=$TOTALWEIGHT; HISTLEN=$HISTORYLENGTH; KEYLEN=$KEYATLEN; SV_FINAL=$SETTLEDVIEW
echo "  weightOf(after)=$W_AFTER  totalWeight(after)=$TW_AFTER  (deposit=$DEPOSIT_WEI)"
if [ "$W_AFTER" -gt 0 ] && [ "$W_AFTER" != "$W_BEFORE" ]; then
  pass "weightOf: EL-applied recordWeight set weightOf($NID)=$W_AFTER (was $W_BEFORE)"
else
  fail "weightOf: did not change via the EL (before=$W_BEFORE after=$W_AFTER)"
fi

echo "  historyLength=$HISTLEN  keyAt(v_eff=$ROT_VEFF) len=${KEYLEN}B"
if [ "$HISTLEN" -ge 1 ] && [ "$KEYLEN" = 128 ]; then
  pass "keyAt: EL-applied recordKey recorded a 128-byte EIP-2537 key at v_eff=$ROT_VEFF (historyLength=$HISTLEN)"
else
  fail "keyAt: rotated key not recorded (historyLength=$HISTLEN, keyAt len=${KEYLEN}B)"
fi

echo "  settledView(final)=$SV_FINAL"
if [ "$SV_FINAL" -gt 0 ]; then
  pass "settledView: EL-applied recordSettled advanced the frontier to $SV_FINAL"
else
  fail "settledView: frontier never advanced (still 0)"
fi

echo
echo "═════════════════════════════════════════════════════"
FINAL_HEAD=$(el_head)
if [ "$FAILS" = 0 ]; then
  echo "RESULT: PASS — real single-node boule↔custom-EL run (BLS chain); Registry at $REGISTRY"
  echo "  reflects the EL-applied rotation (keyAt 128B @ v_eff=$ROT_VEFF, historyLength=$HISTLEN),"
  echo "  weight change (weightOf=$W_AFTER, was $W_BEFORE; totalWeight=$TW_AFTER), and advancing"
  echo "  settledView=$SV_FINAL. EL head=$FINAL_HEAD."
  exit 0
else
  echo "RESULT: FAIL — $FAILS assertion(s) failed (logs in $WORK)."
  echo "--- boule log tail ---"; tail -40 "$BOULE_LOG"
  exit 1
fi
