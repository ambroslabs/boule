# Spinning up a local ambros-p2p testnet on a laptop

This guide walks through running a small ambros-p2p cluster on a single
machine. "Testnet" here means a handful of real node processes talking to
each other over TLS, forming a gossip mesh, and — optionally — running the
HotStuff consensus loop.

Three nodes is the smallest size at which gossip fan-out and dedupe are
meaningful, so the basic walkthrough uses three. The consensus walkthrough
later bumps that to four (the minimum size at which HotStuff tolerates any
node failure: `n = 3f + 1` with `f = 1`). An advanced section at the end
shows a seven-node cluster (`f = 2`) and walks through a rotating-failure
scenario that exercises crash recovery and dynamic membership tolerance.

---

## 1. Prerequisites

- Rust stable, edition 2024 (≥ 1.85). `rust-toolchain.toml` pins the exact
  toolchain; `rustup` picks it up on first build.
- `curl` and `jq` (optional, for poking the HTTP API).
- Three free TCP ports per node (one P2P, one HTTP admin). The recipe
  below uses `7000/7001/7002` for P2P and `8000/8001/8002` for the admin
  API.

Clone and build once:

```sh
git clone https://github.com/zrbecker/ambros-p2p.git
cd ambros-p2p
cargo build --release
```

The release binary lands at `target/release/ambros-p2p`. Debug builds
work too; release is just faster.

---

## 2. How a node is addressed

A node's long-term identity is an Ed25519 keypair. The base58 encoding of
its public key *is* the node's overlay address (the `NodeId`). Two facts
follow:

1. A node's `NodeId` is not known until the first time `ambros-p2p init`
   runs and provisions its key. So the workflow is: **`init` mints the key
   and prints the `NodeId` → paste it into peers' configs → `start`.**
2. Peers can be configured in trust-on-first-use mode (`addr` only), or
   pinned by expected `NodeId`. Pinning is strongly recommended even on a
   laptop — it catches config mix-ups immediately.

Each node reads a TOML config file. The minimum shape is:

```toml
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "file"
path    = "./testnet/node1/node.key"

[api]
listen_addr = "127.0.0.1:8000"
```

When `--config` is omitted, `ambros-p2p` reads from the platform default:

| Resource | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Config | `$XDG_CONFIG_HOME/ambros-p2p/config.toml` (default `~/.config/ambros-p2p/config.toml`) | `~/Library/Application Support/ambros-p2p/config.toml` | `%APPDATA%\ambros-p2p\config.toml` |
| State / WAL / storage | `$XDG_DATA_HOME/ambros-p2p/` (default `~/.local/share/ambros-p2p/`) | `~/Library/Application Support/ambros-p2p/` | `%LOCALAPPDATA%\ambros-p2p\` |

The walkthroughs below pass `--config` explicitly because every node
runs on the same host and would otherwise collide on the default
location. A single-node deployment can omit `--config` entirely.

(The legacy `key_file = "..."` scalar inside `[node]` is still accepted
for backward compatibility but has been superseded by the
`[node.identity]` table — use the table form in new configs.)

---

## 3. Lay out the testnet directory

Pick a workspace outside the repo — each node needs its own data
directory so their key files don't collide.

```sh
mkdir -p testnet/{node1,node2,node3}
```

Create one config per node. Leave the `[[peers]]` blocks empty for now;
we'll fill them in after we know the node IDs.

`testnet/node1/config.toml`:

```toml
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "file"
path    = "./testnet/node1/node.key"

[api]
listen_addr = "127.0.0.1:8000"
cleanup_interval_secs = 60
```

`testnet/node2/config.toml`:

```toml
[node]
listen_addr = "127.0.0.1:7001"

[node.identity]
backend = "file"
path    = "./testnet/node2/node.key"

[api]
listen_addr = "127.0.0.1:8001"
cleanup_interval_secs = 60
```

`testnet/node3/config.toml`:

```toml
[node]
listen_addr = "127.0.0.1:7002"

[node.identity]
backend = "file"
path    = "./testnet/node3/node.key"

[api]
listen_addr = "127.0.0.1:8002"
cleanup_interval_secs = 60
```

---

## 4. Mint each node's identity

`ambros-p2p init` provisions the on-disk key for the file backend and
prints the resulting `NodeId` to stdout. Run it once per node:

```sh
./target/release/ambros-p2p init --config testnet/node1/config.toml
# stdout includes: "provisioned new node key: NodeId = <base58…>"
```

Repeat for `node2` and `node3`. Record the three IDs somewhere you can
paste from. For example:

```
node1: 4k2m…A3p
node2: 9xQ2…7rT
node3: 2bC8…hK1
```

(Your values will be different — every fresh key mints a fresh ID.)

`init` is idempotent: re-running it on an already-provisioned node
prints `node already provisioned: NodeId = <…>` instead of minting a
new key. For read-only key backends (`env`, `exec`, `keyring`), `init`
does not generate a key — it prints an "externally managed" notice and
asks you to provision the key out-of-band before re-running.

---

## 5. Wire the peers together

Add `[[peers]]` entries to each config so nodes dial one another on
startup. Sequential startup (node1 first, then node2 dialing node1, then
node3 dialing both) is sufficient — the TLS transport is bidirectional, so
every pair ends up with exactly one connection.

Append to `testnet/node2/config.toml`:

```toml
[[peers]]
addr    = "127.0.0.1:7000"
node_id = "<NodeId of node1>"
```

Append to `testnet/node3/config.toml`:

```toml
[[peers]]
addr    = "127.0.0.1:7000"
node_id = "<NodeId of node1>"

[[peers]]
addr    = "127.0.0.1:7001"
node_id = "<NodeId of node2>"
```

`node1` needs no `[[peers]]` block — it accepts inbound connections.

> **Why pin `node_id`?** Without it, the TLS handshake trusts whatever
> identity the remote presents (TOFU). Pinning causes the handshake to
> fail closed if the peer's identity doesn't match, which is exactly what
> you want in a testnet where all IDs are known in advance.

---

## 6. Start the testnet

Open three terminals (or use `tmux`). In each one:

```sh
# Terminal 1
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/node1/config.toml

# Terminal 2 (after node1 is up)
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/node2/config.toml

# Terminal 3 (after node2 is up)
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/node3/config.toml
```

You should see log lines on each side announcing the P2P listener, the
HTTP API listener, and (on node2/node3) the outbound dials succeeding.

If `start` exits immediately with `no node key found via the 'file'
backend`, the config points at a key path that hasn't been minted yet
— run `ambros-p2p init --config <path>` first.

---

## 7. Verify the mesh

Each node serves an admin HTTP API on its `[api].listen_addr`. List
connected peers:

```sh
curl -s http://127.0.0.1:8000/peers | jq
curl -s http://127.0.0.1:8001/peers | jq
curl -s http://127.0.0.1:8002/peers | jq
```

Each node should report the other two node IDs. If you see an empty
array, check that the `[[peers]].addr` values and `node_id` values in the
other two configs match the first node's listener and printed ID.

### Gossip a message end-to-end

Post a message to node1; the gossip engine fans it out to node2 and
node3. `expiry` is an absolute RFC 3339 timestamp — pick something a
minute or two in the future.

```sh
EXPIRY=$(date -u -d '+2 minutes' +%Y-%m-%dT%H:%M:%SZ)
curl -s -X POST http://127.0.0.1:8000/messages \
  -H 'content-type: application/json' \
  -d "{\"content\": \"hello cluster\", \"expiry\": \"$EXPIRY\"}"
```

Then confirm it arrived on the other two:

```sh
curl -s http://127.0.0.1:8001/messages | jq
curl -s http://127.0.0.1:8002/messages | jq
```

Both should include `"content": "hello cluster"`. Duplicate POSTs with
the same content + expiry are idempotent — the store dedupes by content
hash.

### Ping a peer over RPC

The ping protocol is a thin wrapper around the RPC layer and is useful
for confirming connectivity and measuring per-hop latency. From node1,
ping node3 (replace `<node3-id>` with the base58 ID you recorded):

```sh
curl -s -X POST http://127.0.0.1:8000/rpc/ping/<node3-id> \
  -H 'content-type: application/json' \
  -d '{"payload": "ping"}'
```

The response echoes the payload back through the RPC round-trip.

---

## 8. Turn on HotStuff consensus

Gossip alone is a functional p2p net, but the point of the project is BFT
consensus. The 3-node setup you just built is fine for gossip but is a
degenerate consensus committee — `n = 3f + 1` means `f = 0` at three
nodes, so any single failure halts the cluster. The smallest meaningful
HotStuff committee is **four nodes**, where `f = 1` and the cluster
tolerates one fault. We'll spin up a fourth node here, then enable
consensus on all four.

### Add node4

Add a `node4` directory and config alongside the existing three:

```sh
mkdir -p testnet/node4
```

`testnet/node4/config.toml`:

```toml
[node]
listen_addr = "127.0.0.1:7003"

[node.identity]
backend = "file"
path    = "./testnet/node4/node.key"

[api]
listen_addr = "127.0.0.1:8003"
cleanup_interval_secs = 60
```

Mint its identity the same way you did for nodes 1–3:

```sh
./target/release/ambros-p2p init --config testnet/node4/config.toml
# stdout includes: "provisioned new node key: NodeId = <base58…>"
```

### Wire all four nodes peer-to-peer

For consensus you want a **full mesh** so the round-robin leader can
broadcast proposals to every other replica without depending on gossip
hops. Each node's config gets `[[peers]]` entries for the other three.
Append to each config (substituting the four node IDs you recorded):

```toml
# testnet/node1/config.toml — add the other three peers
[[peers]]
addr    = "127.0.0.1:7001"
node_id = "<node2-id>"

[[peers]]
addr    = "127.0.0.1:7002"
node_id = "<node3-id>"

[[peers]]
addr    = "127.0.0.1:7003"
node_id = "<node4-id>"
```

Repeat the equivalent block on each of the other three configs (each
node lists the other three peers, never itself).

### Append the consensus section

Append the same `[consensus]` block to all four configs. The
`validators` list must be **byte-identical across every replica** — the
list's ordering determines round-robin leader rotation, and a mismatch
means the committee doesn't agree on whose turn it is. Every node's own
ID must appear in the list.

```toml
[consensus]
validators       = ["<node1-id>", "<node2-id>", "<node3-id>", "<node4-id>"]
genesis_seed_hex = "0000000000000000000000000000000000000000000000000000000000000000"
propose_limit    = 64
timeout_base_ms  = 500
timeout_max_ms   = 5000
storage_dir      = "./testnet/node1/consensus"   # change per-node
```

`storage_dir` makes consensus state durable across restarts (used in the
fault-tolerance experiments below). If omitted, an in-memory backend is
used — acceptable for a throwaway demo but no crash recovery.

> **Bootstrapping notes.** Adding a fifth validator later requires
> editing and restarting every existing replica with the new committee
> list. Dynamic membership changes are out of scope for v1. The
> `genesis_seed_hex` field is a 32-byte hex string — pick a throwaway
> value and make sure every replica uses the same one, or they will
> disagree on the genesis block and refuse to make progress.

### Start the cluster

Start each node in its own terminal (or `tmux` pane). A small startup
stagger lets the dialer tasks settle, but isn't required:

```sh
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/node1/config.toml &
sleep 0.3
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/node2/config.toml &
sleep 0.3
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/node3/config.toml &
sleep 0.3
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/node4/config.toml &
```

Within a few seconds each node's log should show:

```
INFO ambros_p2p: consensus: event loop spawned
INFO ambros_p2p::consensus::node: consensus: committed block height=1 view=2
INFO ambros_p2p::consensus::node: consensus: committed block height=2 view=3
... (steady stream)
```

The `committed block` lines are the proof that consensus is actually
making progress, not just exchanging messages.

### Verify the cluster is healthy

Three checks, in order from cheapest to most thorough.

**1. Are all four nodes connected?** `/peers` should report 3 entries on
every node:

```sh
for p in 8000 8001 8002 8003; do
  echo "node on :$p sees:"
  curl -s http://127.0.0.1:$p/peers | jq -r '.[] | .node_id'
done
```

**2. Is each node committing?** The `/consensus/status` endpoint
publishes a JSON snapshot of consensus-internal state on every event-loop
iteration. `last_committed_height` should be growing on every node:

```sh
for p in 8000 8001 8002 8003; do
  echo "node on :$p:"
  curl -s http://127.0.0.1:$p/consensus/status \
    | jq '{current_view, last_committed_height, self_role, peers_connected}'
done
```

`self_role` reads `"leader(view=N)"` on whichever node is the round-robin
proposer for the current view, `"replica"` on the others. After a few
seconds, `last_committed_height` should be ≥ 1 on every node.

**3. Do all nodes agree on the chain (safety)?** Extract every
`(height, view)` pair each node has committed and confirm any height
that two nodes both committed is at the same view:

```sh
mkdir -p /tmp/ambros-check
for i in 1 2 3 4; do
  port=$((7999 + i))
  # Pull each node's commit log from its tracing output.
  # Assumes you redirected each node's stderr to testnet/nodeN/log.
  grep -oE "height=[0-9]+ view=[0-9]+" testnet/node$i/log \
    | sed -E 's/height=([0-9]+) view=([0-9]+)/\1 \2/' \
    | sort -n -k1 -u > /tmp/ambros-check/n$i.hv
done

violations=0
for h in $(cat /tmp/ambros-check/n*.hv | cut -d' ' -f1 | sort -n -u); do
  views=$(for i in 1 2 3 4; do
    grep "^$h " /tmp/ambros-check/n$i.hv | head -1 | cut -d' ' -f2
  done | sort -u)
  count=$(echo "$views" | wc -w)
  if [ "$count" -gt 1 ]; then
    echo "SAFETY VIOLATION at height=$h: views=$views"
    violations=$((violations+1))
  fi
done
echo "checked $(cat /tmp/ambros-check/n*.hv | wc -l) commit records, $violations violations"
```

A healthy cluster reports `0 violations`. The (height, view) pair is
sufficient to detect a safety violation because two distinct blocks at
the same height would have been proposed in different views, and the
commit log records both.

> The above one-liner assumes you redirected each node's logs to a file
> via `&>> testnet/nodeN/log` or similar. If you ran them inline in
> separate terminals, save the output first or use the `/consensus/status`
> snapshot which exposes the same `last_committed_height` per node.

### Reading `/consensus/status`

The full status payload is intended for live debugging. The fields:

| Field | Meaning |
| --- | --- |
| `current_view` | The view this node believes it is in. Should match (within 1) across all live nodes. |
| `last_committed_height` | Highest block height this node has applied to the state machine. |
| `last_committed_view` | View at which `last_committed_height` was proposed. |
| `locked` | The locked QC (HotStuff's safety lock) — `null` until the first 2-chain forms. |
| `high_qc` | The freshest QC this node has seen — drives proposal authorship. |
| `vote_buckets` | In-flight vote aggregation per `(view, block_hash)`. `signers` < `quorum` means the cluster is gathering signatures. |
| `timeout_buckets` | In-flight timeout-vote aggregation per view. Non-empty during a leader timeout. |
| `parked_proposals` | Proposals received before their parent — usually transient during catch-up. |
| `peers_connected` | The consensus-layer view of live peers; should mirror `validators \ {self}` on a healthy cluster. |
| `mempool_size` | Pending application commands the leader will pull from on its next proposal. |

A gossip-only node (no `[consensus]` section in its config) returns
`404 Not Found` from this endpoint — a one-liner check for whether
consensus is even configured.

---

## 9. Fault-tolerance experiments

The point of HotStuff is that it keeps committing under faults. These
experiments stress the cluster you just built and the bigger one in §9b,
and verify that **safety holds** (no two nodes commit different blocks
at the same height) and **liveness holds** (survivors keep committing).

For the scripts below, redirect each node's logs to a file so you can
post-process them. The pattern is:

```sh
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/node1/config.toml \
  > testnet/node1/log 2>&1 &
PID1=$!
# ... etc per node, recording PID1, PID2, PID3, PID4
```

### 9a. f = 1: kill one node, verify survivors

With the four-node cluster from §8 running, snapshot the survivors'
commit counts, kill one node, then check that the other three keep
committing:

```sh
# Cluster is running; PID2 is the node we'll kill.
sleep 3   # let the cluster reach steady state
echo "before kill:"
for i in 1 3 4; do
  echo "  n$i: $(grep -c 'committed block' testnet/node$i/log) commits"
done
echo "killing n2 (pid=$PID2)"
kill -9 $PID2
sleep 6
echo "after kill (survivors should have grown):"
for i in 1 3 4; do
  c=$(grep -c "committed block" testnet/node$i/log)
  last=$(grep "committed block" testnet/node$i/log | tail -1 | grep -oE 'height=[0-9]+')
  echo "  n$i: $c commits, $last"
done
```

You should see each survivor's commit count higher than its pre-kill
snapshot. The post-kill rate is significantly slower than steady state
— with `timeout_base_ms = 500` and one of four leaders dead, every
fourth view eats a timeout-certificate round (~500ms). Expect roughly
one commit per second post-kill versus tens per second on the happy path.

Re-run the safety verifier from §8 to confirm no two survivors disagree
on any committed height. After a single-node kill it should still report
zero violations.

### 9b. f = 2: rotating failures with seven nodes

Bumping to `n = 7` gives `f = 2` — the cluster tolerates two simultaneous
failures. The interesting test is that the two failures don't have to
be the same two nodes for all time: a node can crash, recover, and
participate while a different node fails. HotStuff's fault tolerance is
**per-snapshot**, not per-identity.

#### Setup

A seven-node cluster is too tedious to bootstrap by hand. Use the
following helper to mint keys and write configs:

```sh
mkdir -p testnet7

# Step 1: write the per-node config and provision its key with `init`.
for i in 1 2 3 4 5 6 7; do
  mkdir -p testnet7/node$i
  cat > testnet7/node$i/config.toml <<EOF
[node]
listen_addr = "127.0.0.1:$((27000 + i))"

[node.identity]
backend = "file"
path    = "testnet7/node$i/node.key"

[api]
listen_addr = "127.0.0.1:$((28000 + i))"
cleanup_interval_secs = 60
EOF
  ./target/release/ambros-p2p init --config testnet7/node$i/config.toml \
    > testnet7/node$i/init.log
done

# Step 2: collect node IDs (parsed from each `init` log) and write
# final configs with [consensus] + peers.
NODE_IDS=$(for i in 1 2 3 4 5 6 7; do
  grep -oE 'NodeId = [^ ]+' testnet7/node$i/init.log \
    | head -1 | awk '{print $3}'
done)
VALIDATORS=$(echo "$NODE_IDS" | sed 's/^/"/; s/$/"/' | paste -sd ',' -)

for i in 1 2 3 4 5 6 7; do
  PEERS=""
  for j in 1 2 3 4 5 6 7; do
    [ "$i" = "$j" ] && continue
    NJ=$(sed -n "${j}p" <<< "$NODE_IDS")
    PEERS="$PEERS
[[peers]]
addr    = \"127.0.0.1:$((27000 + j))\"
node_id = \"$NJ\"
"
  done
  cat > testnet7/node$i/config.toml <<EOF
[node]
listen_addr = "127.0.0.1:$((27000 + i))"

[node.identity]
backend = "file"
path    = "testnet7/node$i/node.key"

[api]
listen_addr = "127.0.0.1:$((28000 + i))"
cleanup_interval_secs = 60

[consensus]
validators       = [$VALIDATORS]
storage_dir      = "testnet7/node$i/consensus"
timeout_base_ms  = 500
timeout_max_ms   = 5000
$PEERS
EOF
done
```

#### The rotating-failure scenario

Define a small launcher and snapshot helper, then run the scenario:

```sh
launch() {
  RUST_LOG=info ./target/release/ambros-p2p start --config testnet7/node$1/config.toml \
    >> testnet7/node$1/log 2>&1 &
  eval "PID$1=\$!"
}

snap() {
  echo "== $1 =="
  for i in 1 2 3 4 5 6 7; do
    if [ -f testnet7/node$i/log ]; then
      c=$(grep -c "committed block" testnet7/node$i/log 2>/dev/null || echo 0)
      h=$(grep "committed block" testnet7/node$i/log 2>/dev/null \
        | tail -1 | grep -oE "height=[0-9]+" || echo "-")
      echo "  n$i: $c commits, $h"
    fi
  done
}

# t=0: launch all 7
for i in 1 2 3 4 5 6 7; do launch $i; sleep 0.2; done
sleep 3
snap "t=3s, all healthy"

# t=3s: kill n2 and n5 (at the f=2 boundary)
kill -9 $PID2 $PID5
sleep 5
snap "t=8s, n2 + n5 dead (5 honest)"

# t=8s: restart n2 (it has on-disk state and recovers via block sync)
launch 2
sleep 4
snap "t=12s, n2 healed, only n5 dead"

# t=12s: kill n4 (now the dead set is {n4, n5} — different from before)
kill -9 $PID4
sleep 6
snap "t=18s, n4 + n5 dead, n2 fully participating"

# Shut down survivors
for i in 1 2 3 6 7; do
  pid_var="PID$i"
  kill -TERM ${!pid_var} 2>/dev/null
done
wait 2>/dev/null
```

#### What to look for

A healthy run produces output like:

```
== t=3s, all healthy ==
  n1: 78 commits, height=78
  n2: 78 commits, height=78
  ... (all within 1-2 of each other)

== t=8s, n2 + n5 dead (5 honest) ==
  n1: 86 commits, height=86       ← survivors gained ~8
  n2: 78 commits, height=78       ← frozen at pre-kill
  n5: 78 commits, height=78       ← frozen
  n3: 86 commits, height=86
  ...

== t=12s, n2 healed, only n5 dead ==
  n2: 109 commits, height=109     ← caught up to live chain via block sync
  n1: 109 commits, height=109     ← rate accelerated (only 1 dead)
  ...

== t=18s, n4 + n5 dead, n2 fully participating ==
  n1: 113 commits, height=118     ← survivors progressed past kill
  n2: 113 commits, height=118     ← formerly dead, now contributing
  n4: 109 commits, height=109     ← frozen at second kill
  n5: 78 commits, height=78       ← still frozen
  ...
```

Three properties to verify:

1. **Liveness across both faulty windows.** Survivors gain commits in
   both the t=3→8s window (n2+n5 down) and the t=12→18s window (n4+n5
   down). Both are `f = 2` configurations.
2. **Recovery and re-participation.** n2 was dead for ~5 seconds, missed
   ~30 blocks, restarted, caught up to the live chain via block sync,
   and then fully participated in committing past the second kill point.
3. **Safety is preserved across rotating failures.** Run the §8 safety
   verifier against `testnet7/node*/log` after the run completes:

   ```sh
   for i in 1 2 3 4 5 6 7; do
     grep -oE "height=[0-9]+ view=[0-9]+" testnet7/node$i/log \
       | sed -E 's/height=([0-9]+) view=([0-9]+)/\1 \2/' \
       | sort -n -k1 -u > /tmp/n$i.hv
   done
   violations=0
   for h in $(cat /tmp/n*.hv | cut -d' ' -f1 | sort -n -u); do
     views=$(for i in 1 2 3 4 5 6 7; do
       grep "^$h " /tmp/n$i.hv | head -1 | cut -d' ' -f2
     done | sort -u | tr '\n' ' ')
     count=$(echo "$views" | wc -w)
     [ "$count" -gt 1 ] && { echo "VIOLATION h=$h views=$views"; violations=$((violations+1)); }
   done
   echo "violations: $violations"
   ```

   Expect zero violations across the union of every committed height.
   No two nodes ever committed different blocks at the same height,
   even though the down-set rotated mid-run.

> **What this isn't.** "Kill the process" simulates **fail-stop**: a
> node simply stops sending and receiving. True Byzantine behavior
> (sending malformed messages, equivocating proposals, withholding votes
> selectively) requires a node binary patched to misbehave. The HotStuff
> safety theorem covers both fail-stop and Byzantine up to the same `f`
> bound, but the live-cluster scenario above only exercises fail-stop.
> Byzantine-message coverage is provided by the safety core's property
> tests in `src/consensus/hotstuff/step.rs`, which mix arbitrary
> Byzantine votes/proposals/NewViews with honest delivery and assert
> `assert_no_conflicting_commits`.

---

## 10. Shut down and clean up

Ctrl-C each node. The binary traps `SIGINT`, drains connections (flushing
TLS `close_notify` so peers don't log an ugly unclean-shutdown error),
then exits within a few seconds.

To reset state entirely — fresh keys, empty stores — remove the testnet
directory:

```sh
rm -rf testnet testnet7
```

Your node IDs will change after this, so remember to re-wire `[[peers]]`
(and `[consensus].validators`, if enabled) after minting fresh keys.

---

## 11. Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `/peers` returns `[]` on every node | One or more `[[peers]].node_id` values don't match the actual node IDs (typo or stale copy). Re-check the printed `node ID: ...` lines. |
| `Address already in use` on start | Something else is bound to the P2P or API port. Edit `listen_addr` to use another port, or kill the stale process. |
| Messages don't propagate | Mesh isn't formed — check `/peers` first. If peers are present but `/messages` diverges, check clocks: `expiry` comparisons use wall-clock time, and a very skewed laptop clock can make messages land already-expired. |
| `no node key found via the '<backend>' backend` | The configured key backend is empty — run `ambros-p2p init --config <path>` (file/encrypted-file) or provision the key out-of-band (env/exec/keyring) before retrying `start`. |
| `refusing to start in production without an explicit [node.identity]` | You set `AMBROS_ENV=production` or passed `--production`. For a laptop testnet, unset both and let the default file backend kick in. |
| Consensus nodes never commit | The committees don't match. Every replica's `[consensus].validators` list must be the exact same strings in the exact same order, and `genesis_seed_hex` must be identical. Check `/consensus/status` on every node — divergent `validator_set` arrays are the smoking gun. |
| Consensus committing in steady state then stalls | A node went down and the cluster dropped below quorum. With `n = 3f + 1`, you need at least `2f + 1` live to make progress. `/consensus/status` shows `peers_connected` shrinking and `timeout_buckets` accumulating without firing. |
| `/consensus/status` returns 404 | The `[consensus]` section is missing from that node's config, or the node was started without `--config`. |
| `last_committed_height` stays at 0 while `current_view` keeps rising | The cluster is forming TCs but no QC chain is reaching the 3-chain commit rule. Common causes: mismatched `validators` or `genesis_seed_hex`, or a permanent network partition among a subset. |
| A restarted node sits at an old `last_committed_height` | Block-sync is in flight; give it a few seconds. If it doesn't catch up, check that `peers_connected` reports the live cluster and that the `storage_dir` path is the same one this node used previously. |

---

## Reference: commands used above

```sh
# Build
cargo build --release

# Bootstrap a node (idempotent; mints the file/encrypted-file key,
# creates the consensus storage_dir, prints the NodeId)
./target/release/ambros-p2p init --config testnet/nodeN/config.toml

# Start a node
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/nodeN/config.toml

# Print help (shows all subcommands including `key migrate`)
./target/release/ambros-p2p --help

# Admin API — gossip-only fields
curl -s http://127.0.0.1:8000/peers
curl -s http://127.0.0.1:8000/messages
curl -s -X POST http://127.0.0.1:8000/messages \
     -H 'content-type: application/json' \
     -d '{"content":"hi","expiry":"<RFC3339 timestamp>"}'
curl -s -X POST http://127.0.0.1:8000/rpc/ping/<peer-node-id> \
     -H 'content-type: application/json' \
     -d '{"payload":"ping"}'

# Admin API — consensus (only when [consensus] is enabled)
curl -s http://127.0.0.1:8000/consensus/status | jq

# Cluster sizing
#   n = 3f + 1  →  4 nodes tolerates 1 fault, 7 nodes tolerates 2.
#   Quorum = 2f + 1 of n.
```

For deeper reading: `cargo doc --document-private-items --open` renders
the module-level architecture notes, and the `tests/integration_test.rs`
file is a working reference for programmatic multi-node spin-up. The
sim-based property tests in `src/consensus/hotstuff/step.rs` and
`src/consensus/sim.rs` are the canonical reference for what consensus
behaviour is expected to hold across happy-path, crash, and Byzantine
scenarios.
