#!/usr/bin/env bash
# Multi-validator reth testnet + e2e assertions (#632).
#
# Launches N boule validators, each driving its OWN external reth execution
# layer (distinct datadirs/ports from one genesis.json), peers the reths so the
# EVM tx-pool gossips (#634), runs the cluster past several leader rotations,
# then asserts the properties that prove the reth backend works across
# independent EL processes:
#
#   1. liveness    — the chain advances past 2N committed blocks, so HotStuff's
#                    round-robin leader schedule has had every validator lead;
#   2. agreement   — all N reths report a byte-identical EVM state root at a deep
#                    committed height (every node executed every leader's
#                    payloads to the same state);
#   3. tx landing  — a tx submitted to ONE node's reth is mined and visible, in
#                    the same block, on ALL N reths (tx-pool gossip + ordering);
#   4. no divergence — no node ever logged `consensus_state_divergence_detected`.
#
# Prereqs on PATH: reth, cast (foundry), openssl, jq, curl, and a boule binary
# built WITH the reth feature:
#     cargo build --release -p boule-cli --features reth
#
# Usage:   ./testnet.sh            # 4 validators (default)
#          N=7 ./testnet.sh        # 7 validators
#          BOULE=/path/to/boule ./testnet.sh
# Exit code 0 = all assertions passed; non-zero = a failure (and which one).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
N="${N:-4}"
BOULE="${BOULE:-$DIR/../../target/release/boule}"
GENESIS="${GENESIS:-$DIR/genesis.json}"
WORK="${WORK:-/tmp/boule-reth-testnet}"
# anvil dev account #0 (prefunded in genesis.json).
SENDER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RECIPIENT=0x000000000000000000000000000000000000dEaD

for bin in reth cast openssl jq curl python3; do
  command -v "$bin" >/dev/null || { echo "FATAL: '$bin' not found on PATH"; exit 2; }
done
if [ ! -x "$BOULE" ]; then
  echo "FATAL: boule binary not found at $BOULE"
  echo "       build it first:  cargo build --release -p boule-cli --features reth"
  exit 2
fi

# Port scheme (per validator i, 1..N): reth authrpc 8550+i, eth 8544+i, p2p
# 30303+i; boule consensus 7000+i, api 8000+i.
reth_auth() { echo $((8550 + $1)); }
reth_http() { echo $((8544 + $1)); }
reth_p2p()  { echo $((30303 + $1)); }
boule_p2p() { echo $((7000 + $1)); }
eth_rpc()   { echo "http://127.0.0.1:$(reth_http "$1")"; }

PIDS=()
cleanup() {
  echo "── tearing down ──"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  pkill -f "$WORK/node" 2>/dev/null || true
  pkill -f "$WORK/reth" 2>/dev/null || true
}
trap cleanup EXIT

rpc() { # $1 host-port-url, $2 method, $3 params-json
  curl -s -X POST "$1" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"
}
head_of() { rpc "$(eth_rpc "$1")" eth_blockNumber '[]' | jq -r '.result // "0x0"' | xargs printf '%d'; }
root_at() { rpc "$(eth_rpc "$1")" eth_getBlockByNumber "[\"$2\",false]" | jq -r '.result.stateRoot // "none"'; }

rm -rf "$WORK"; mkdir -p "$WORK"
JWT="$WORK/jwt.hex"; openssl rand -hex 32 > "$JWT"

echo "── starting $N reth instances ──"
for i in $(seq 1 "$N"); do
  reth node --chain "$GENESIS" --datadir "$WORK/reth$i" \
    --authrpc.addr 127.0.0.1 --authrpc.port "$(reth_auth "$i")" --authrpc.jwtsecret "$JWT" \
    --http --http.addr 127.0.0.1 --http.port "$(reth_http "$i")" \
    --http.api "eth,net,web3,txpool,admin" \
    --disable-discovery --ipcdisable --port "$(reth_p2p "$i")" \
    >"$WORK/reth$i.log" 2>&1 &
  PIDS+=("$!")
done

echo "── waiting for reth RPCs + collecting enodes ──"
declare -a ENODE
for i in $(seq 1 "$N"); do
  for _ in $(seq 1 30); do
    e=$(rpc "$(eth_rpc "$i")" admin_nodeInfo '[]' | jq -r '.result.enode // empty')
    [ -n "$e" ] && { ENODE[$i]="$e"; break; }
    sleep 1
  done
  [ -n "${ENODE[$i]:-}" ] || { echo "FATAL: reth$i never came up"; exit 2; }
done
SEED=$(root_at 1 0x0); SEED=${SEED#0x}

echo "── minting keys + writing configs ──"
declare -a NID
for i in $(seq 1 "$N"); do
  mkdir -p "$WORK/node$i"
  cat >"$WORK/node$i/init.toml" <<EOF
[node]
listen_addr = "127.0.0.1:$(boule_p2p "$i")"
[node.identity]
backend = "file"
path = "$WORK/node$i/node.key"
[api]
listen_addr = "127.0.0.1:$((8000 + i))"
EOF
  NID[$i]=$("$BOULE" init --config "$WORK/node$i/init.toml" 2>&1 | grep -oP 'NodeId = \K\S+')
done
VALIDATORS=$(for i in $(seq 1 "$N"); do printf '"%s",' "${NID[$i]}"; done | sed 's/,$//')

echo "── starting $N boule validators (each → its own reth, reths peered) ──"
for i in $(seq 1 "$N"); do
  BOOT=$(for j in $(seq 1 "$N"); do [ "$j" -ne "$i" ] && printf '"127.0.0.1:%d",' "$(boule_p2p "$j")"; done | sed 's/,$//')
  PEERS=$(for j in $(seq 1 "$N"); do [ "$j" -ne "$i" ] && printf '"%s",' "${ENODE[$j]}"; done | sed 's/,$//')
  cat >"$WORK/node$i/node.toml" <<EOF
[node]
listen_addr = "127.0.0.1:$(boule_p2p "$i")"
[node.identity]
backend = "file"
path = "$WORK/node$i/node.key"
[api]
listen_addr = "127.0.0.1:$((8000 + i))"
[overlay]
bootstrap_addrs = [$BOOT]
[consensus]
validators = [$VALIDATORS]
genesis_seed_hex = "$SEED"
storage_dir = "$WORK/node$i/consensus"
timeout_base_ms = 1000
timeout_max_ms = 8000
min_block_interval_ms = 500
[consensus.application]
backend = "reth"
engine_url = "http://127.0.0.1:$(reth_auth "$i")"
eth_url = "$(eth_rpc "$i")"
jwt_secret_path = "$JWT"
fee_recipient = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
reth_peers = [$PEERS]
EOF
  "$BOULE" start --config "$WORK/node$i/node.toml" >"$WORK/node$i.log" 2>&1 &
  PIDS+=("$!")
done

# Run well past 2N committed blocks so the round-robin leader schedule has had
# every validator lead at least twice.
TARGET=$(( 2 * N + 8 ))
echo "── running until height ≥ $TARGET (covers ≥2 full leader rotations) ──"
for _ in $(seq 1 120); do
  h=$(head_of 1); echo "   node1 reth head=$h"
  [ "$h" -ge "$TARGET" ] && break
  sleep 2
done

FAILS=0
fail() { echo "  ✗ $1"; FAILS=$((FAILS + 1)); }
pass() { echo "  ✓ $1"; }
echo
echo "════════════════════ ASSERTIONS ════════════════════"

# 1. Liveness / leader rotation.
H1=$(head_of 1)
if [ "$H1" -ge "$TARGET" ]; then
  pass "liveness: chain reached height $H1 (≥ 2N+8 = $TARGET → every validator has led)"
else
  fail "liveness: chain only reached height $H1 (target $TARGET)"
fi

# 2. State-root agreement at a deep committed height held by every node.
MINHEAD=$H1
for i in $(seq 1 "$N"); do h=$(head_of "$i"); [ "$h" -lt "$MINHEAD" ] && MINHEAD=$h; done
CHECK=$(( MINHEAD - 3 )); [ "$CHECK" -lt 1 ] && CHECK=1
HX=$(printf '0x%x' "$CHECK")
REF=$(root_at 1 "$HX"); AGREE=1
for i in $(seq 1 "$N"); do
  r=$(root_at "$i" "$HX")
  [ "$r" = "$REF" ] || { AGREE=0; echo "    node$i root@$CHECK=$r ≠ $REF"; }
done
if [ "$AGREE" = 1 ] && [ "$REF" != "none" ]; then
  pass "agreement: all $N reths share state root $REF at height $CHECK"
else
  fail "agreement: reths disagree on the state root at height $CHECK"
fi

# 3. A tx submitted to ONE node lands, in the same block, on ALL nodes.
echo "  … submitting a tx to node1's reth"
TXH=$(cast send --rpc-url "$(eth_rpc 1)" --private-key "$SENDER_PK" "$RECIPIENT" --value 1ether --json 2>/dev/null | jq -r '.transactionHash // empty')
if [ -z "$TXH" ]; then
  fail "tx landing: cast send returned no tx hash"
else
  sleep 4
  LANDED=1; BLK=""
  for i in $(seq 1 "$N"); do
    rcpt=$(rpc "$(eth_rpc "$i")" eth_getTransactionReceipt "[\"$TXH\"]")
    bn=$(echo "$rcpt" | jq -r '.result.blockNumber // "none"')
    [ "$bn" = "none" ] && { LANDED=0; echo "    node$i has no receipt for $TXH"; continue; }
    [ -z "$BLK" ] && BLK=$bn
    [ "$bn" = "$BLK" ] || { LANDED=0; echo "    node$i mined the tx in block $bn ≠ $BLK"; }
  done
  if [ "$LANDED" = 1 ]; then
    pass "tx landing: $TXH mined in block $((BLK)) on all $N reths"
  else
    fail "tx landing: the tx is not uniformly reflected across reths"
  fi
fi

# 4. No node ever flagged execution-state divergence.
DIV=0
for i in $(seq 1 "$N"); do
  # grep -c prints the count (0 on no match) and exits 1 when zero; capture the
  # count and normalize, rather than letting the exit status double-append.
  c=$(grep -c 'consensus_state_divergence_detected' "$WORK/node$i.log" 2>/dev/null)
  c=${c:-0}
  [ "$c" -ne 0 ] && { DIV=$((DIV + c)); echo "    node$i logged $c divergence event(s)"; }
done
if [ "$DIV" = 0 ]; then
  pass "no divergence: consensus_state_divergence_detected is zero on all $N nodes"
else
  fail "no divergence: $DIV total divergence events across the cluster"
fi

# 5. EVM-native staking (#655): a `withdraw` to the staking predeploy removes
#    a validator from the boule set, and the cluster keeps committing. This
#    exercises the whole P1→P2 path on real reth — predeploy event → eth_getLogs
#    in commit → StakeSource → validator_updates → reconfig.
STAKING=0x0000000000000000000000000000000000000b0e
boule_status() { curl -s "http://127.0.0.1:$((8000 + $1))/consensus/status"; }
# boule NodeIds are base58; the contract's `bytes32 nodeId` arg needs the
# 32-byte hex. Decode here (no external python module needed).
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

REMOVE_B58="${NID[$N]}"            # remove the last validator; survivors = 1..N-1
REMOVE_HEX=$(b58_to_hex "$REMOVE_B58")
BEFORE=$(boule_status 1 | jq -r '.validator_set | length')
echo "  … unbonding validator $REMOVE_B58 ($REMOVE_HEX) via $STAKING (set size before=$BEFORE)"
# A large amount saturates the ledger to zero regardless of the seeded stake,
# so the validator is removed (weight 0). Sent to node1's reth; gossip carries
# it to whichever validator leads next.
if ! cast send --rpc-url "$(eth_rpc 1)" --private-key "$SENDER_PK" "$STAKING" \
      "withdraw(bytes32,uint256)" "$REMOVE_HEX" 1000000 --json >/dev/null 2>&1; then
  fail "staking: cast send withdraw failed"
fi

# Poll the survivors until the app-driven reconfig has materialised and taken
# effect (commit-latency + the mint's v_eff settle margin → ~tens of seconds).
REMOVED=0
for _ in $(seq 1 60); do
  ok=1
  for i in $(seq 1 "$N"); do
    [ "$i" -eq "$N" ] && continue          # the removed node need not keep following
    st=$(boule_status "$i")
    len=$(echo "$st" | jq -r '.validator_set | length')
    has=$(echo "$st" | jq -r --arg v "$REMOVE_B58" '.validator_set | index($v) // "no"')
    { [ "$len" = "$((N - 1))" ] && [ "$has" = "no" ]; } || ok=0
  done
  [ "$ok" = 1 ] && { REMOVED=1; break; }
  sleep 2
done
if [ "$REMOVED" = 1 ]; then
  pass "staking: a withdraw removed $REMOVE_B58 — set shrank to $((N - 1)) on all survivors"
else
  fail "staking: validator set did not shrink to $((N - 1)) after the withdraw"
fi

# Liveness under the reduced set: a survivor keeps committing.
HB=$(head_of 1); sleep 8; HA=$(head_of 1)
if [ "$HA" -gt "$HB" ]; then
  pass "staking: cluster keeps committing under the reduced set ($HB → $HA)"
else
  fail "staking: cluster stalled after the removal ($HB → $HA)"
fi

echo "═════════════════════════════════════════════════════"
if [ "$FAILS" = 0 ]; then
  echo "RESULT: PASS — $N-validator reth cluster commits in agreement across leader rotations, lands a tx, and an EVM staking withdraw removes a validator (#655)."
  exit 0
else
  echo "RESULT: FAIL — $FAILS assertion(s) failed (logs under $WORK)."
  exit 1
fi
