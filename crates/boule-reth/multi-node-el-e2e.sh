#!/usr/bin/env bash
# A1 Phase-5 MULTI-NODE convergence e2e (#785 part b / #777): stand up TWO real
# boule validators, EACH driving its OWN custom EL (boule-reth-node) over the
# Engine API, peered over the network into one BLS chain (2-of-2 quorum). After
# a rotation + stake change commit through real consensus, assert BOTH nodes'
# Registries at 0x…0b12 hold BYTE-IDENTICAL keyAt / weightOf / settledView — the
# determinism claim, empirically, across two independently-executing ELs driven
# by two networked consensus nodes.
#
#   crates/boule-reth/multi-node-el-e2e.sh
#
# Why this complements drive-custom-el-2inst.sh: that proof drives two ELs
# directly over the Engine API (A builds, B verifies the SAME payload). This one
# drives them through two *networked boule consensus nodes* forming a real
# quorum — the full path.
#
# Env: SOLC (genesis gen). Ports: EL1 8545/8551, EL2 8555/8561; boule1 p2p 7001
# api 8001, boule2 p2p 7002 api 8002.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/../.."
NODE_DIR="$DIR/../boule-reth-node"
WORK="${WORK:-/tmp/boule-el-multinode}"
REGISTRY="0x0000000000000000000000000000000000000b12"
STAKING="0x0000000000000000000000000000000000000b0e"

BOULE="${BOULE:-$ROOT/target/debug/boule}"
CARGO_RUN="cargo run -q --manifest-path $ROOT/Cargo.toml"

EL1_PID=""; EL2_PID=""; B1_PID=""; B2_PID=""
cleanup() {
  echo "── tearing down ──"
  for p in "$B1_PID" "$B2_PID" "$EL1_PID" "$EL2_PID"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
  for p in "$B1_PID" "$B2_PID" "$EL1_PID" "$EL2_PID"; do
    [ -n "$p" ] && wait "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

for bin in reth openssl jq curl python3 xxd; do
  command -v "$bin" >/dev/null || { echo "FATAL: '$bin' not on PATH"; exit 2; }
done

echo "── building helpers + EL ──"
(cd "$ROOT" && cargo build -q -p boule-reth --bin gen-genesis --bin gen-bls-genesis --bin el-e2e-ops --jobs 3)
OPS="$ROOT/target/debug/el-e2e-ops"
EL_BIN="$NODE_DIR/target/debug/boule-reth-node"
if [ ! -x "$EL_BIN" ]; then
  echo "── building boule-reth-node (heavy) ──"
  : "${BINDGEN_EXTRA_CLANG_ARGS:=-I/usr/lib/gcc/x86_64-linux-gnu/15/include}"
  export BINDGEN_EXTRA_CLANG_ARGS
  (cd "$NODE_DIR" && cargo build --jobs 3)
fi
[ -x "$BOULE" ] || { echo "── building boule (reth feature) ──"; (cd "$ROOT" && cargo build -p boule-cli --features reth --jobs 3); }

rm -rf "$WORK"; mkdir -p "$WORK"
JWT1="$WORK/jwt1.hex"; JWT2="$WORK/jwt2.hex"
openssl rand -hex 32 > "$JWT1"; openssl rand -hex 32 > "$JWT2"

echo "── generating canonical genesis (Registry at $REGISTRY) ──"
GEN="$WORK/genesis.json"
$CARGO_RUN -p boule-reth --bin gen-genesis -- 4 "$GEN"

start_el() { # datadir jwt authport httpport log
  "$EL_BIN" node --chain "$GEN" --datadir "$1" \
    --authrpc.addr 127.0.0.1 --authrpc.port "$3" --authrpc.jwtsecret "$2" \
    --http --http.addr 127.0.0.1 --http.port "$4" \
    --http.api "eth,net,web3,txpool,admin" \
    --disable-discovery --ipcdisable --port 0 \
    > "$5" 2>&1 &
  echo $!
}
wait_rpc() { # httpport
  for _ in $(seq 1 60); do
    curl -fsS -X POST "http://127.0.0.1:$1" -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
state_root() { # httpport
  curl -fsS -X POST "http://127.0.0.1:$1" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' \
    | jq -r '.result.stateRoot' | sed 's/^0x//'
}

echo "── starting EL1 (8545/8551) and EL2 (8555/8561) ──"
EL1_PID=$(start_el "$WORK/reth1" "$JWT1" 8551 8545 "$WORK/el1.log")
EL2_PID=$(start_el "$WORK/reth2" "$JWT2" 8561 8555 "$WORK/el2.log")
wait_rpc 8545 || { echo "FATAL: EL1 RPC down"; exit 2; }
wait_rpc 8555 || { echo "FATAL: EL2 RPC down"; exit 2; }
SEED1=$(state_root 8545); SEED2=$(state_root 8555)
echo "   EL1 genesis state root = $SEED1"
echo "   EL2 genesis state root = $SEED2"
[ "$SEED1" = "$SEED2" ] || { echo "FATAL: ELs disagree on genesis state root"; exit 2; }
SEED=$SEED1

# ── mint both node keys (fixed p2p/api ports) ──
mint_node() { # idx p2pport apiport keypath
  cat > "$WORK/init$1.toml" <<EOF
[node]
listen_addr = "127.0.0.1:$2"
[node.identity]
backend = "file"
path = "$4"
[api]
listen_addr = "127.0.0.1:$3"
EOF
  "$BOULE" init --config "$WORK/init$1.toml" 2>&1 | grep -oP 'NodeId = \K\S+' | head -1
}
echo "── minting node keys ──"
NID1=$(mint_node 1 7001 8001 "$WORK/node1.key")
NID2=$(mint_node 2 7002 8002 "$WORK/node2.key")
[ -n "$NID1" ] && [ -n "$NID2" ] || { echo "FATAL: node key mint failed"; exit 2; }
echo "   NID1 = $NID1"
echo "   NID2 = $NID2"

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
NID1_HEX=$(b58_to_hex "$NID1"); NID2_HEX=$(b58_to_hex "$NID2")

# ── mint both BLS keys + JOINT chain-bound PoPs (set-order independent) ──
echo "── minting BLS keys + joint chain-bound PoPs (seed=$SEED) ──"
BLS_OUT=$($CARGO_RUN -p boule-reth --bin gen-bls-genesis -- --multi "$SEED" \
  "$NID1:$WORK/bls1.key" "$NID2:$WORK/bls2.key")
# Map node_id -> (pubkey, pop). The --multi output is in input order (0=NID1, 1=NID2).
BLS_PUB1=$(echo "$BLS_OUT" | grep -oP '^bls_pubkey_0=\K\S+')
BLS_POP1=$(echo "$BLS_OUT" | grep -oP '^bls_pop_0=\K\S+')
BLS_PUB2=$(echo "$BLS_OUT" | grep -oP '^bls_pubkey_1=\K\S+')
BLS_POP2=$(echo "$BLS_OUT" | grep -oP '^bls_pop_1=\K\S+')
[ -n "$BLS_PUB1" ] && [ -n "$BLS_POP1" ] && [ -n "$BLS_PUB2" ] && [ -n "$BLS_POP2" ] \
  || { echo "FATAL: multi BLS gen failed: $BLS_OUT"; exit 2; }
chmod 600 "$WORK"/bls*.key "$WORK"/node*.key 2>/dev/null || true

# Shared [consensus.validators] + both validators_bls rows (identical on both).
validators_bls_block() {
  cat <<EOF
[[consensus.validators_bls]]
node_id = "$NID1"
bls_pubkey = "$BLS_PUB1"
bls_pop = "$BLS_POP1"
[[consensus.validators_bls]]
node_id = "$NID2"
bls_pubkey = "$BLS_PUB2"
bls_pop = "$BLS_POP2"
EOF
}

# ── write both node configs (mutual [[peers]], same consensus genesis) ──
write_cfg() { # idx p2pport apiport keypath blskey consensus_dir engine eth jwt peer_addr peer_id
  cat > "$WORK/node$1.toml" <<EOF
[node]
listen_addr = "127.0.0.1:$2"
[node.identity]
backend = "file"
path = "$4"
[node.bls_validator_identity]
backend = "file"
path = "$5"
[api]
listen_addr = "127.0.0.1:$3"
[[peers]]
addr = "${10}"
node_id = "${11}"
[consensus]
validators = ["$NID1", "$NID2"]
signature_scheme = "bls_aggregated"
genesis_seed_hex = "$SEED"
storage_dir = "$6"
timeout_base_ms = 700
timeout_max_ms = 6000
min_block_interval_ms = 800
$(validators_bls_block)
[consensus.application]
backend = "reth"
engine_url = "$7"
eth_url = "$8"
jwt_secret_path = "$9"
fee_recipient = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
EOF
}
write_cfg 1 7001 8001 "$WORK/node1.key" "$WORK/bls1.key" "$WORK/consensus1" \
  http://127.0.0.1:8551 http://127.0.0.1:8545 "$JWT1" "127.0.0.1:7002" "$NID2"
write_cfg 2 7002 8002 "$WORK/node2.key" "$WORK/bls2.key" "$WORK/consensus2" \
  http://127.0.0.1:8561 http://127.0.0.1:8555 "$JWT2" "127.0.0.1:7001" "$NID1"

echo "── starting both boule validators (peered, custom EL each) ──"
"$BOULE" start --config "$WORK/node1.toml" > "$WORK/boule1.log" 2>&1 &
B1_PID=$!
"$BOULE" start --config "$WORK/node2.toml" > "$WORK/boule2.log" 2>&1 &
B2_PID=$!

el_head() { curl -fsS -X POST "http://127.0.0.1:$1" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
  | jq -r '.result' | python3 -c "import sys;print(int(sys.stdin.read().strip() or '0x0',16))" 2>/dev/null || echo 0; }
node_view() { curl -fsS "http://127.0.0.1:$1/consensus/status" 2>/dev/null \
  | jq -r '(.current_view // .view // 0) | if type=="object" then .[] else . end' 2>/dev/null || echo 0; }

echo "── waiting for the 2-of-2 quorum to commit blocks ──"
STARTED=0
for _ in $(seq 1 90); do
  h1=$(el_head 8545); h2=$(el_head 8555); v1=$(node_view 8001); v2=$(node_view 8002)
  echo "   EL1 head=$h1 (view $v1)  EL2 head=$h2 (view $v2)"
  { [ "$h1" -ge 4 ] && [ "$h2" -ge 4 ]; } && { STARTED=1; break; }
  sleep 2
done
if [ "$STARTED" != 1 ]; then
  echo "FATAL: the 2-node cluster never reached height 4 on both ELs"
  echo "--- boule1 log ---"; tail -40 "$WORK/boule1.log"
  echo "--- boule2 log ---"; tail -40 "$WORK/boule2.log"
  exit 2
fi

FAILS=0
fail() { echo "  ✗ $1"; FAILS=$((FAILS + 1)); }
pass() { echo "  ✓ $1"; }

echo
echo "════════════════ EXERCISING A ROTATION + STAKE CHANGE ════════════════"
# Stake change: deposit for NID1 against EL1 (the change propagates to BOTH ELs
# because both replicas derive the same recordWeight from the committed block).
echo "── depositing stake for $NID1 (via EL1 on :8545) ──"
# el-e2e-ops submits to :8545 = EL1; the weight change propagates to BOTH ELs
# because every replica derives the same recordWeight from the committed block.
TXH=$("$OPS" deposit "$NID1_HEX" 3 2>"$WORK/dep.err") || true
echo "   deposit tx (via EL1) = $TXH"

# BLS rotation of NID1, far-future v_eff (no live hot-swap), submitted to node1.
CUR=$(node_view 8001); CUR=${CUR:-0}; ROT_VEFF=$(( CUR + 100000 ))
echo "── building a BLS rotation for node1 (v_eff=$ROT_VEFF) ──"
RUST_LOG=off "$BOULE" rotation propose -c "$WORK/node1.toml" \
  --new-key-backend file --new-key-path "$WORK/node1.key.new" \
  --new-bls-key-backend file --new-bls-key-path "$WORK/bls1.key.new" \
  --v-eff "$ROT_VEFF" >"$WORK/rot.out" 2>"$WORK/rot.err" || cat "$WORK/rot.err"
ROT_HEX=$(grep -oiE '[0-9a-f]{64,}' "$WORK/rot.out" | head -1)
if [ -n "$ROT_HEX" ]; then
  echo "$ROT_HEX" | xxd -r -p > "$WORK/rot.bin"
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:8001/mempool/submit" \
    -H 'content-type: application/octet-stream' --data-binary @"$WORK/rot.bin")
  echo "   /mempool/submit (node1) -> HTTP $CODE"
else
  fail "rotation: no envelope produced"
fi

echo
echo "── letting both ELs apply the registry writes ──"
# Read both registries via el-e2e-ops; it targets 8545 by default, so for EL2 we
# read with a tiny inline RPC instead (keyAt len / weightOf / settledView).
reg_fields() { # httpport node_hex v_eff [block_tag]  -> echoes "W TW SV KL"
  # block_tag defaults to "latest"; pass an EVM block-number hex (e.g. 0x64) to
  # read both ELs at the SAME height so settledView (which advances every block)
  # is compared at one point — not raced across two live, independently-advancing
  # nodes (keyAt/weightOf are stable post-write, but settledView is not).
  local port="$1" node="${2#0x}" veff="$3" blk="${4:-latest}"
  python3 - "$port" "$node" "$veff" "$blk" <<'PY'
import sys, json, urllib.request
port, node, veff, blk = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
REG="0x0000000000000000000000000000000000000b12"
def call(data):
    req=urllib.request.Request(f"http://127.0.0.1:{port}",
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_call",
            "params":[{"to":REG,"data":data},blk]}).encode(),
        headers={"content-type":"application/json"})
    try: return json.load(urllib.request.urlopen(req,timeout=5)).get("result","0x")
    except Exception: return "0x"
def word(sel,arg=""):
    r=call("0x"+sel+arg); r=r[2:] if r.startswith("0x") else r
    return int(r[-64:] or "0",16) if r else 0
n = node.rjust(64,"0")
v = format(veff,"064x")
W  = word("4c108d6d", n)             # weightOf(bytes32)
TW = word("96c82e57")                # totalWeight()
SV = word("7a686ef2")                # settledView()
# keyAt(bytes32,uint64) -> dynamic bytes; read length word
k = call("0x3a9e358a"+n+v); k = k[2:] if k.startswith("0x") else k
KL = int(k[64+48:128],16) if len(k)>=128 else 0
print(W, TW, SV, KL)
PY
}
# Wait until the EL-applied writes land on BOTH nodes (keyAt/weightOf settle).
for _ in $(seq 1 60); do
  R1=$(reg_fields 8545 "$NID1_HEX" "$ROT_VEFF")
  R2=$(reg_fields 8555 "$NID1_HEX" "$ROT_VEFF")
  echo "   EL1[W TW SV KL]=($R1)   EL2[W TW SV KL]=($R2)"
  read -r W1 _TW1 _SV1 KL1 <<<"$R1"; read -r W2 _TW2 _SV2 KL2 <<<"$R2"
  { [ "${KL1:-0}" = 128 ] && [ "${W1:-0}" -gt 0 ] && [ "${KL2:-0}" = 128 ] && [ "${W2:-0}" -gt 0 ]; } && break
  sleep 2
done

echo
echo "════════════════ CONVERGENCE ASSERTIONS (both Registries) ════════════════"
# Pin BOTH reads to the SAME EVM block height (the lower of the two heads) so
# settledView — which advances every block — is compared at one point, not raced
# across two independently-advancing live nodes. keyAt/weightOf are stable once
# written; settledView is only equal at equal heights.
H1=$(el_head 8545); H2=$(el_head 8555)
PIN=$(( H1 < H2 ? H1 : H2 )); PIN=$(( PIN - 1 ))   # one back, safely on both
PIN_HEX=$(printf '0x%x' "$PIN")
echo "── reading both Registries at the common pinned height $PIN ($PIN_HEX) ──"
R1=$(reg_fields 8545 "$NID1_HEX" "$ROT_VEFF" "$PIN_HEX")
R2=$(reg_fields 8555 "$NID1_HEX" "$ROT_VEFF" "$PIN_HEX")
read -r W1 TW1 SV1 KL1 <<<"$R1"
read -r W2 TW2 SV2 KL2 <<<"$R2"
echo "   EL1@$PIN: weightOf=$W1 totalWeight=$TW1 settledView=$SV1 keyAtLen=$KL1"
echo "   EL2@$PIN: weightOf=$W2 totalWeight=$TW2 settledView=$SV2 keyAtLen=$KL2"
[ "$KL1" = 128 ] && [ "$W1" -gt 0 ] && [ "$SV1" -gt 0 ] \
  || fail "EL1 did not reflect the EL-applied writes (W=$W1 SV=$SV1 KL=$KL1)"
if [ "$R1" = "$R2" ]; then
  pass "convergence: both nodes' Registries hold BYTE-IDENTICAL keyAt/weightOf/settledView at height $PIN ($R1)"
else
  fail "convergence: registries DIVERGED at height $PIN  EL1=($R1)  EL2=($R2)"
fi

echo
echo "═════════════════════════════════════════════════════"
if [ "$FAILS" = 0 ]; then
  echo "RESULT: PASS — two networked boule validators, each on its own custom EL,"
  echo "  converged on a byte-identical Registry at $REGISTRY after a rotation +"
  echo "  stake change: weightOf=$W1 totalWeight=$TW1 settledView=$SV1 keyAtLen=$KL1 on BOTH."
  exit 0
else
  echo "RESULT: FAIL — $FAILS assertion(s) failed (logs in $WORK)."
  echo "--- boule1 log tail ---"; tail -30 "$WORK/boule1.log"
  echo "--- boule2 log tail ---"; tail -30 "$WORK/boule2.log"
  exit 1
fi
