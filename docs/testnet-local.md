# Spinning up a local ambros-p2p testnet on a laptop

This guide walks through running a small ambros-p2p cluster on a single
machine. "Testnet" here means a handful of real node processes talking to
each other over TLS, forming a gossip mesh, and — optionally — running the
HotStuff consensus loop.

Three nodes is the smallest interesting size: it exercises the fan-out
dedupe path in gossip, and it is the minimum committee size at which the
HotStuff pacemaker has a non-trivial leader rotation. The walkthrough uses
three nodes, but the recipe scales to as many as your laptop has RAM for.

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

1. A node's `NodeId` is not known until the first time it runs and
   generates (or loads) its key. So the workflow is: **start once to mint
   the key → copy the printed `NodeId` into peers' configs → restart.**
2. Peers can be configured in trust-on-first-use mode (`addr` only), or
   pinned by expected `NodeId`. Pinning is strongly recommended even on a
   laptop — it catches config mix-ups immediately.

Each node reads a TOML config file. The minimum shape is:

```toml
[node]
listen_addr = "127.0.0.1:7000"
key_file    = "./testnet/node1/node.key"

[api]
listen_addr = "127.0.0.1:8000"
```

Everything below builds on that.

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
key_file    = "./testnet/node1/node.key"

[api]
listen_addr = "127.0.0.1:8000"
cleanup_interval_secs = 60
```

`testnet/node2/config.toml`:

```toml
[node]
listen_addr = "127.0.0.1:7001"
key_file    = "./testnet/node2/node.key"

[api]
listen_addr = "127.0.0.1:8001"
cleanup_interval_secs = 60
```

`testnet/node3/config.toml`:

```toml
[node]
listen_addr = "127.0.0.1:7002"
key_file    = "./testnet/node3/node.key"

[api]
listen_addr = "127.0.0.1:8002"
cleanup_interval_secs = 60
```

---

## 4. Mint each node's identity

Start each node once so it generates its key, then stop it and grab the
printed `NodeId`. `RUST_LOG=info` makes the `node ID: ...` line visible.

```sh
RUST_LOG=info ./target/release/ambros-p2p --config testnet/node1/config.toml
# look for: "node ID: <base58…>"  — copy it, then Ctrl-C
```

Repeat for `node2` and `node3`. Record the three IDs somewhere you can
paste from. For example:

```
node1: 4k2m…A3p
node2: 9xQ2…7rT
node3: 2bC8…hK1
```

(Your values will be different — every fresh key mints a fresh ID.)

Tip: if typing `RUST_LOG=info` gets tedious, it is equivalent to running
the binary with the default tracing filter `ambros_p2p=info` inherited
from `main.rs`, so you can just `export RUST_LOG=info` for the session.

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
RUST_LOG=info ./target/release/ambros-p2p --config testnet/node1/config.toml

# Terminal 2 (after node1 is up)
RUST_LOG=info ./target/release/ambros-p2p --config testnet/node2/config.toml

# Terminal 3 (after node2 is up)
RUST_LOG=info ./target/release/ambros-p2p --config testnet/node3/config.toml
```

You should see log lines on each side announcing the P2P listener, the
HTTP API listener, and (on node2/node3) the outbound dials succeeding.

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

## 8. (Optional) Turn on HotStuff consensus

Gossip alone is a functional p2p net, but the point of the project is
BFT consensus. You can opt every node into HotStuff by adding a
`[consensus]` section to each config. Consensus is currently a
work-in-progress (see issues #21–#24), so treat this as experimental
rather than a general test harness.

The committee (`validators`) must be **byte-identical across every
replica** — the list's ordering determines leader rotation. It must also
include this node's own ID.

Append the same `[consensus]` block to all three configs, substituting
the base58 node IDs you recorded:

```toml
[consensus]
validators       = ["<node1-id>", "<node2-id>", "<node3-id>"]
genesis_seed_hex = "0000000000000000000000000000000000000000000000000000000000000000"
propose_limit    = 64
timeout_base_ms  = 200
timeout_max_ms   = 10000

# Durable storage directory. If omitted, the node uses in-memory
# storage — fine for a throwaway testnet, not for crash-recovery tests.
storage_dir = "./testnet/node1/consensus"   # change per-node
```

Restart each node in the same order. Logs now include
`consensus: event loop spawned` and periodic view transitions.

> **Bootstrapping notes.** Because every validator has to list every
> other validator's ID, adding a fourth node after the fact requires
> editing and restarting all of them. Plan the committee up front. The
> `genesis_seed_hex` field is a 32-byte hex string — pick a throwaway
> value and make sure every replica uses the same one, or they will
> disagree on the genesis block and refuse to make progress.

### Inspect live consensus state

With `[consensus]` enabled, each node serves
`GET /consensus/status`. It returns a JSON snapshot of the consensus
node's current view, the locked/high QC it holds, any partial vote or
timeout buckets, parked proposals, and the connected peer set. The
snapshot is published once per event-loop iteration, so reads are
cheap and never contend with the hot path.

```sh
curl -s http://127.0.0.1:8000/consensus/status | jq
curl -s http://127.0.0.1:8001/consensus/status | jq
curl -s http://127.0.0.1:8002/consensus/status | jq
```

On a healthy cluster each node reports `last_committed_height` > 0
and `current_view` > 0 within a few seconds of startup, and
`peers_connected` mirrors the validator set minus self. The field
`self_role` reads `"leader(view=N)"` on whichever node is the round-
robin proposer for the current view, and `"replica"` on everyone
else.

If a cluster is wedged, `/consensus/status` replaces the usual
grepping routine: a node stuck with `last_committed_height` unchanged
while `current_view` keeps advancing means liveness without progress
(look at `timeout_buckets`); a node with a growing `parked_proposals`
list is missing a parent block in its block-sync path. A gossip-only
node (no `[consensus]` section) returns `404 Not Found` here, which
is a useful one-liner check for whether consensus is configured.

---

## 9. Shut down and clean up

Ctrl-C each node. The binary traps `SIGINT`, drains connections (flushing
TLS `close_notify` so peers don't log an ugly unclean-shutdown error),
then exits within a few seconds.

To reset state entirely — fresh keys, empty stores — remove the testnet
directory:

```sh
rm -rf testnet
```

Your node IDs will change after this, so remember to re-wire `[[peers]]`
(and `[consensus].validators`, if enabled) after minting fresh keys.

---

## 10. Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `/peers` returns `[]` on every node | One or more `[[peers]].node_id` values don't match the actual node IDs (typo or stale copy). Re-check the printed `node ID: ...` lines. |
| `Address already in use` on start | Something else is bound to the P2P or API port. Edit `listen_addr` to use another port, or kill the stale process. |
| Messages don't propagate | Mesh isn't formed — check `/peers` first. If peers are present but `/messages` diverges, check clocks: `expiry` comparisons use wall-clock time, and a very skewed laptop clock can make messages land already-expired. |
| `refusing to start in production without an explicit [node.identity]` | You set `AMBROS_ENV=production` or passed `--production`. For a laptop testnet, unset both and let the default file backend kick in. |
| Consensus nodes log view timeouts forever | The committees don't match. Every replica's `[consensus].validators` list must be the exact same strings in the exact same order, and `genesis_seed_hex` must be identical. |

---

## Reference: commands used above

```sh
# Build
cargo build --release

# Start a node
RUST_LOG=info ./target/release/ambros-p2p --config testnet/nodeN/config.toml

# Print help (shows the `key migrate` subcommand too)
./target/release/ambros-p2p --help

# Admin API
curl -s http://127.0.0.1:8000/peers
curl -s http://127.0.0.1:8000/messages
curl -s -X POST http://127.0.0.1:8000/messages \
     -H 'content-type: application/json' \
     -d '{"content":"hi","expiry":"<RFC3339 timestamp>"}'
curl -s -X POST http://127.0.0.1:8000/rpc/ping/<peer-node-id> \
     -H 'content-type: application/json' \
     -d '{"payload":"ping"}'
curl -s http://127.0.0.1:8000/consensus/status | jq  # only when [consensus] is enabled
```

For deeper reading: `cargo doc --document-private-items --open` renders
the module-level architecture notes, and the `tests/integration_test.rs`
file is a working reference for programmatic multi-node spin-up.
