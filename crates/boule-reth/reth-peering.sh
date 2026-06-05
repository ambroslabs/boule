#!/usr/bin/env bash
# Two-phase reth devp2p peering for a boule testnet (#826).
#
# The load-bearing half of the #826 fix: boule's in-storage EL-catch-up replay
# (#635/#826) bridges a gap only while it is RETAINED. A follower whose reth was
# wiped, or that joined past the retention window, has an UNRETAINED gap — the
# only trustless way it catches up is reth self-syncing (snap/full) from PEER
# reths over devp2p. This script wires that peering.
#
# It uses reth's `--trusted-peers` (NOT admin_addPeer): peering is a pure
# deployment concern that needs NO admin RPC namespace, so it works on the
# locked-down public deployment (#822/#825) where reth exposes only eth,net,web3
# on loopback. It is the mechanism validated by hand on #826 (a follower bridged
# a ~4700-block gap to lag 0 once given the validators' reths as trusted peers).
#
# Because an enode embeds reth's secp256k1 pubkey — derived/persisted on first
# boot, only KNOWN post-boot — peering is inherently two-phase:
#
#   PHASE 1 (scrape):  read each reth's enode pubkey from its log line
#                        "P2P networking initialized enode=enode://<pubkey>@..."
#                      The pubkey is STABLE across restarts (persisted in the
#                      datadir's node key), so one scrape per node suffices.
#   PHASE 2 (emit):    for each node, write a trusted-peers file listing the
#                      enodes of the nodes it should peer — with the REACHABLE
#                      IP/port substituted for reth's advertised 127.0.0.1 (the
#                      advertisement is loopback; a peer must dial the real host).
#                      The supervisor (entrypoint / systemd / run-local) restarts
#                      reth with `--trusted-peers $(cat <file>)`.
#
# NAT / external-ip note: `--trusted-peers` drives OUTBOUND dials, and the dialer
# uses the enode's IP directly — so the advertised-as-127.0.0.1 endpoint does not
# matter as long as EVERY node lists every peer with the peer's reachable IP
# (a symmetric trusted mesh, which is what this emits). No `--nat`/external-ip is
# required for the trusted-peer dial-out to connect. (Open discovery, which DOES
# need a correct advertised endpoint, is left disabled.)
#
# Usage:
#   reth-peering.sh scrape  <reth.log> <reachable-host> <p2p-port>
#       -> prints   enode://<pubkey>@<reachable-host>:<p2p-port>   (or exits 1)
#
#   reth-peering.sh build   <out-dir> <node-spec>...
#       where each <node-spec> is  name=<n>:log=<path>:host=<ip>:port=<p>:peers=<n1,n2,...>
#       -> writes <out-dir>/<name>.trusted-peers (comma-joined enodes) per node,
#          peering each node ONLY to its listed peers (mirrors the consensus
#          bootstrap topology: a full mesh here, a sentry fan-out if so listed).
set -uo pipefail

# Read reth's persisted enode pubkey from its log and rebuild the enode at the
# reachable host:port (reth advertises 127.0.0.1). Strips ANSI colour codes the
# reth logger emits. Returns 1 if the line has not appeared yet (reth not up).
enode_from_log() { # log host port
  local log="$1" host="$2" port="$3" pub
  [ -f "$log" ] || return 1
  pub=$(sed -E 's/\x1b\[[0-9;]*m//g' "$log" \
    | grep -oE 'enode://[0-9a-fA-F]{128}@' \
    | head -1 | sed -E 's#enode://##; s/@$//')
  [ -n "$pub" ] || return 1
  printf 'enode://%s@%s:%s' "$pub" "$host" "$port"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  scrape)
    log="${1:?reth.log}"; host="${2:?reachable-host}"; port="${3:?p2p-port}"
    # Poll briefly: the supervisor may call this right after starting reth.
    for _ in $(seq 1 60); do
      e=$(enode_from_log "$log" "$host" "$port") && { echo "$e"; exit 0; }
      sleep 1
    done
    echo "FATAL: no 'P2P networking initialized enode=' line in $log yet" >&2
    exit 1
    ;;
  build)
    out="${1:?out-dir}"; shift
    mkdir -p "$out"
    declare -A LOG HOST PORT PEERS
    names=()
    for spec in "$@"; do
      n=""; l=""; h=""; p=""; pr=""
      IFS=':' read -ra parts <<<"$spec"
      for kv in "${parts[@]}"; do
        case "$kv" in
          name=*)  n="${kv#name=}" ;;
          log=*)   l="${kv#log=}" ;;
          host=*)  h="${kv#host=}" ;;
          port=*)  p="${kv#port=}" ;;
          peers=*) pr="${kv#peers=}" ;;
        esac
      done
      [ -n "$n" ] || { echo "FATAL: spec missing name=: $spec" >&2; exit 2; }
      names+=("$n"); LOG[$n]="$l"; HOST[$n]="$h"; PORT[$n]="$p"; PEERS[$n]="$pr"
    done
    # Phase 1: scrape each node's enode (at its own reachable host:port).
    declare -A ENODE
    for n in "${names[@]}"; do
      e=$(enode_from_log "${LOG[$n]}" "${HOST[$n]}" "${PORT[$n]}") \
        || { echo "FATAL: could not scrape enode for $n from ${LOG[$n]}" >&2; exit 1; }
      ENODE[$n]="$e"
      echo "   scraped $n -> $e" >&2
    done
    # Phase 2: per node, join the enodes of ITS listed peers (topology-faithful).
    for n in "${names[@]}"; do
      out_list=""; sep=""
      IFS=',' read -ra want <<<"${PEERS[$n]}"
      for pn in "${want[@]}"; do
        [ -n "$pn" ] || continue
        [ "$pn" = "$n" ] && continue
        [ -n "${ENODE[$pn]:-}" ] || { echo "WARN: $n peers unknown node $pn; skipping" >&2; continue; }
        out_list="$out_list$sep${ENODE[$pn]}"; sep=","
      done
      printf '%s' "$out_list" > "$out/$n.trusted-peers"
      echo "   wrote $out/$n.trusted-peers ($(echo "$out_list" | tr ',' '\n' | grep -c .) peer(s))" >&2
    done
    ;;
  *)
    echo "usage: reth-peering.sh {scrape <log> <host> <port> | build <out> <spec>...}" >&2
    exit 2
    ;;
esac
