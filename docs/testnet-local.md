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

### Network identity vs. validator identity

`[node.identity]` is the **network** key: it backs the TLS handshake and
its base58 public key is the overlay `NodeId` other peers dial. When a
node also runs HotStuff consensus it needs a second key — the
**validator** key — to sign proposals, votes, and timeout messages.

By default the validator key is the network key (single-key mode, the
historical behavior; a deprecation warning fires at startup when
consensus is enabled without an explicit validator slot). To split them,
add a sibling `[node.validator_identity]` table that names any of the
same backends:

```toml
[node.identity]
backend = "file"
path    = "./testnet/node1/node.key"

[node.validator_identity]
backend = "encrypted-file"
path    = "./testnet/node1/validator.key"
passphrase_env = "AMBROS_VALIDATOR_PASSPHRASE"
```

Splitting them lets you rotate the TLS key (via `key migrate` or out-of-
band) without churning the validator's consensus identity, and lets the
validator key live on a colder backend than the always-online network
key. Both keys are minted on first start the same way as the single-key
case — the binary logs `network node ID: ...` and (when distinct)
`validator node ID: ...`. The values that go in `[consensus].validators`
across the cluster are the **validator** node IDs.

> **Live cluster routing.** The dispatch layer currently routes consensus
> messages by validator pubkey, while the p2p layer addresses peers by
> their TLS pubkey. As long as the two pubkeys match (single-key mode, or
> a `[node.validator_identity]` that resolves to the same key bytes as
> `[node.identity]`), routing works. Independently rotating the validator
> key requires the validator-set reconfiguration runbook (issue #140) to
> register a `(validator pubkey → network address)` mapping; until that
> lands the binary warns at startup if the two pubkeys differ.

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

### Inspect the resolved config

`ambros-p2p config` prints the **fully-resolved** view: the file
contents *plus* every default the node would fill in if started right
now. It's the answer to questions like "what timeout is this node
actually using?" without remembering the schema:

```sh
./target/release/ambros-p2p config --config testnet/node1/config.toml | grep timeout
# timeout_base_ms = 200
# timeout_max_ms = 10000
```

For programmatic access, `--format json` pipes cleanly into `jq`:

```sh
./target/release/ambros-p2p config --config testnet/node1/config.toml --format json \
    | jq '.consensus.timeout_base_ms'
```

Other modes: `--raw` prints the file as-written (skipping default
expansion), `--path` prints the resolved config path and exits, and
`--edit` opens the file in `$EDITOR` / `$VISUAL` and validates the
result on save.

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
tolerates one fault.

Spinning a four-node cluster up by hand — minting four keys, copying
four IDs, threading each into the other three configs, appending
byte-identical `[consensus]` blocks — is enough ceremony that we ship
a workspace binary, `testnet`, that does it for you. The §9b
fault-tolerance walkthrough also drives the cluster through this
binary; the same one handles steady-state setup here. Operators who
need to write configs by hand can model after the schema in
[§3 Lay out the testnet directory](#3-lay-out-the-testnet-directory)
and the annotated block under
[§8 What the driver writes](#what-the-driver-writes) below.

### Build the driver

`cargo build --release` builds both binaries; if you ran it in §1 you
already have them:

```sh
cargo build --release
ls target/release/ambros-p2p target/release/testnet
```

### Generate the cluster

`testnet new` lays out a per-node workdir, mints each node's identity,
and writes final configs with the validator list, peer list, and
consensus tuning baked in. It refuses to clobber an existing layout
— if `state.json` already exists, `new` exits with an error and asks
you to pick a fresh `--workdir` or delete the old one:

```sh
./target/release/testnet new --nodes 4 --seed 1 --workdir testnet4 \
    --ambros-bin ./target/release/ambros-p2p
```

This produces:

```
testnet4/
├── state.json              # driver bookkeeping (node IDs, addresses, PIDs)
├── events.jsonl            # append-only log of every driver action
├── node1/
│   ├── config.toml         # full config — schema below
│   ├── node.key            # minted by `ambros-p2p init`
│   ├── addr.json           # `addr_file` written on bind, read by the driver
│   ├── consensus/          # WAL + block store (storage_dir)
│   ├── pid                 # written by `up`, removed by `down`
│   └── log                 # captured stderr (driver redirects)
├── node2/ ...
├── node3/ ...
└── node4/ ...
```

<a id="what-the-driver-writes"></a>

#### What the driver writes

Each per-node `config.toml` is the same shape you'd write by hand:

```toml
[node]
listen_addr = "127.0.0.1:<auto>"
addr_file   = "testnet4/node1/addr.json"

[node.identity]
backend = "file"
path    = "testnet4/node1/node.key"

[api]
listen_addr = "127.0.0.1:<auto>"
cleanup_interval_secs = 60

[overlay]
mode          = "gossip"
target_degree = 8

[consensus]
validators      = ["<node1-id>", "<node2-id>", "<node3-id>", "<node4-id>"]
storage_dir     = "testnet4/node1/consensus"
timeout_base_ms = 200
timeout_max_ms  = 2000

[[peers]]
addr    = "127.0.0.1:<node2-p2p>"
node_id = "<node2-id>"
# … one [[peers]] block per bootstrap neighbour
```

Notes worth knowing:

- The `validators` list is **byte-identical across every replica**. The
  list's ordering determines round-robin leader rotation, and a
  mismatch means the committee doesn't agree on whose turn it is.
- `storage_dir` makes consensus state durable across restarts (used in
  the fault-tolerance experiments below). Omitting it falls back to an
  in-memory backend — fine for a throwaway demo but with no crash
  recovery.
- `[overlay].target_degree` is the partial-mesh fan-out the gossip
  overlay maintains. The driver bootstraps each node with a small
  ring-neighbour `[[peers]]` block; gossip discovers the rest. Pass
  `--target-degree T` to override.
- `genesis_seed_hex` and `propose_limit` are omitted — every replica
  picks up the same defaults, which is sufficient for a laptop
  cluster. Set them by hand when reproducing a specific genesis or
  when stress-testing the proposer.
- Bounded-cache caps live under a `[consensus.limits]` sub-table
  (`vote_bucket_capacity`, `parked_proposals_capacity`,
  `pending_blocks_capacity`, `timeout_buckets_capacity`,
  `mempool_capacity`, all default 1024 except `parked_proposals_capacity`
  which defaults to 256). Forced evictions are reported in
  `/consensus/status` under `cache_evictions` and emit a structured
  INFO trace tagged `cache=<name>`. The driver doesn't write the
  table; add it to `testnet4/nodeN/config.toml` post-`new` if you
  need to override.

> **Bootstrapping notes.** Adding a fifth validator later requires
> editing and restarting every existing replica with the new committee
> list. Dynamic membership changes are out of scope for v1. The
> `genesis_seed_hex` field is a 32-byte hex string — when you do set
> one, make sure every replica uses the same one, or they will
> disagree on the genesis block and refuse to make progress.

### Bring the cluster up

```sh
./target/release/testnet up --workdir testnet4
```

The driver spawns each node in the background, captures stderr to
`testnet4/nodeN/log`, records each PID in `testnet4/nodeN/pid`, and
returns once the four processes are running. Within a few seconds
each log file should contain:

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

**1. Snapshot.** `testnet snap` reads `/consensus/status` on every node
and tabulates the answer — connectivity, current view, last committed
height, role:

```sh
./target/release/testnet snap --workdir testnet4
```

```
   node  status        view   height  peers  role
  node1  up(54320)       28       27      3  replica
  node2  up(54321)       28       27      3  leader(view=28)
  node3  up(54322)       27       26      3  replica
  node4  up(54323)       28       27      3  replica
```

`self_role` reads `"leader(view=N)"` on whichever node is the
round-robin proposer for the current view, `"replica"` on the others.
After a few seconds, `height` should be ≥ 1 on every node and
`peers` should be 3 (the other three replicas).

**2. Per-node detail.** `testnet info <node>` prints the full
`/consensus/status` payload, and `testnet info <node> peers` lists
that node's direct gossip peers:

```sh
./target/release/testnet info node1 --workdir testnet4
./target/release/testnet info node1 peers --workdir testnet4
```

**3. Safety.** `testnet verify-safety` extracts every `(height, view)`
commit pair from every node's log and reports any height where two
nodes recorded different views — the smoking gun for a safety
violation. Exits non-zero on a violation, so it composes into CI:

```sh
./target/release/testnet verify-safety --workdir testnet4
# verify-safety: 0 violations
```

The (height, view) pair is sufficient because two distinct blocks at
the same height would have been proposed in different views, and the
commit log records both. The parser tolerates the ANSI color codes
that `tracing-subscriber`'s pretty formatter emits, so a passing run
actually means consistency, not "grep happened to miss a colored
field".

### Reading `/consensus/status`

The full status payload (`testnet info <node>`, or `curl` directly)
is intended for live debugging. The fields:

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
experiments stress the four-node cluster from §8 and the bigger one in
§9b, and verify that **safety holds** (no two nodes commit different
blocks at the same height) and **liveness holds** (survivors keep
committing). The driver handles log capture, PID tracking, and the
safety check, so the experiments collapse to a handful of subcommands.

### 9a. f = 1: kill one node, verify survivors

With the four-node cluster from §8 still up, snapshot the cluster,
SIGKILL one node, wait for the survivors to keep committing past a
new height, then re-snapshot and re-verify safety:

```sh
./target/release/testnet snap --workdir testnet4
./target/release/testnet kill node2 --workdir testnet4
./target/release/testnet wait --all-reach-height 30 --workdir testnet4
./target/release/testnet snap --workdir testnet4
./target/release/testnet verify-safety --workdir testnet4
```

`snap` after the kill should report `node2` as `down` and the other
three nodes' `height` higher than the pre-kill snapshot. The post-kill
commit rate is significantly slower than steady state — with
`timeout_base_ms = 200` and one of four leaders dead, every fourth view
eats a timeout-certificate round. Expect roughly one commit per
hundreds of milliseconds post-kill versus tens of commits per second on
the happy path; pick a `--all-reach-height` target that gives the
survivors enough headroom over the pre-kill height to actually exercise
the dead-leader rotation.

`verify-safety` should still report zero violations: a single-node kill
in an `f = 1` cluster is exactly within the fault budget, so no two
survivors will commit different blocks at the same height. Bring `node2`
back with `testnet up node2 --workdir testnet4` once you're done — the
restart triggers the block-sync catch-up path covered in §9b.

### 9b. f = 2: rotating failures with seven nodes

Bumping to `n = 7` gives `f = 2` — the cluster tolerates two simultaneous
failures. The interesting test is that the two failures don't have to
be the same two nodes for all time: a node can crash, recover, and
participate while a different node fails. HotStuff's fault tolerance is
**per-snapshot**, not per-identity.

The driver scales the §8 recipe to any committee size. `testnet new
--nodes 7` lays out a seven-node ring and writes final configs the
same way it did for the four-node cluster, and the same fault-injection
primitives (`scenario`, `kill`, `wait`, `verify-safety`) apply.

#### One-shot rotating-failure run

```sh
./target/release/testnet new --nodes 7 --seed 1 --workdir testnet7 \
    --ambros-bin ./target/release/ambros-p2p
./target/release/testnet scenario rotating-failure-7n-f2 --seed 1 \
    --workdir testnet7 --ambros-bin ./target/release/ambros-p2p
./target/release/testnet down --workdir testnet7
```

`new` lays out a seven-node ring under `testnet7/` the same way it did
in §8, except that with `n = 7` the bootstrap `[[peers]]` block per node
is just the two ring neighbours `i ± 1 mod 7` (the gossip overlay
discovers the rest through peer-list gossip).

`scenario rotating-failure-7n-f2 --seed 1` brings the cluster up if
it isn't already, waits for every node to commit through height 5,
SIGKILLs two random nodes (the `--seed 1` choice is reproducible),
waits for the survivors to commit *ten more* blocks beyond their
pre-kill heights (an honest "did the survivors keep advancing?"
predicate, not just a height target the cluster might have already
crossed before the kill), then runs the §8 safety verifier across
every per-node log. The seed is recorded in `testnet7/events.jsonl`
so a failing run can be replayed verbatim.

`down` SIGTERMs every live node (escalating to SIGKILL after a 3s
grace) and reaps the per-node `pid` files. It's idempotent — safe to
run after a `Ctrl-C` interrupted scenario, or twice in a row.

#### Inspecting the cluster

While the cluster is up:

```sh
./target/release/testnet ls          --workdir testnet7   # static topology
./target/release/testnet snap        --workdir testnet7   # live commit/view/peers
./target/release/testnet info node3  --workdir testnet7   # full /consensus/status
./target/release/testnet info node3 peers --workdir testnet7
./target/release/testnet logs node3  --workdir testnet7 --tail 80
./target/release/testnet telemetry   --workdir testnet7
./target/release/testnet verify-safety --workdir testnet7
```

`snap` reads `/consensus/status` on every node and tabulates the
result:

```
   node  status        view   height  peers  role
  node1  up(54320)       28       27      6  replica
  node2  up(54321)       28       27      6  leader(view=28)
  node3  up(54322)       27       26      6  replica
  ...
```

`telemetry` tallies the consensus / block-sync counters that would
otherwise require ad-hoc grep over each log: `consensus_resumed`,
`block_sync_request_emitted`, `block_sync_response_received`,
`proposal_rejected_unknown_parent`, `gossip_send_to_dispatched`.

`verify-safety` is the same §8 cross-node `(height, view)` consistency
check. Running it after a scenario re-verifies that the fault window
didn't introduce a divergent commit; it exits non-zero on a violation
and prints the divergent views per node.

#### Crash recovery

A common follow-up to "kill one node" is "bring it back, watch it
catch up, then kill a different one". The driver expresses that as a
sequence of `kill` / `up` / `wait` calls:

```sh
./target/release/testnet kill node2  --workdir testnet7
./target/release/testnet wait --node node2 --catch-up-to-cluster --tolerance 2 \
    --workdir testnet7    # only meaningful after a subsequent `up node2`
./target/release/testnet up node2    --workdir testnet7
./target/release/testnet wait --node node2 --catch-up-to-cluster --tolerance 2 \
    --workdir testnet7
```

The `wait --catch-up-to-cluster` predicate is the answer to "how
long do I sleep after a restart?" — it polls
`last_committed_height` on the restarted node and the rest of the
live cluster, and returns when the gap closes within `--tolerance`.
Block-sync walks back one parent per pacemaker tick, so the wait time
is still bounded by the gap (issue #185 tracks the planned bulk-range
RPC + dedicated retry timer), but the driver no longer
under-or-overshoots a fixed sleep.

The block-sync round-trip is visible at `RUST_LOG=info`; `telemetry`
exposes the same events as a tabular summary rather than asking
operators to grep:

- `consensus_resumed` (once, on a node's restart) — reports the
  recovered `last_committed_height`, `last_voted_view`, and
  `high_qc_view`.
- `proposal_rejected_unknown_parent` + `block_sync_request_emitted`
  (one pair per fresh proposal arriving at the restarted node while
  it's still missing intermediate ancestors) — confirms it's asking
  peers for the missing parents rather than silently dropping the
  proposal.
- `block_sync_response_received` (one per parent the cluster serves
  back) — confirms the round-trip completed.
- `gossip_send_to_dispatched` (one per emitted `BlockRequest`,
  `target_is_direct` reporting whether the requested peer was a
  current direct neighbour). Under the sparse-mesh `[[peers]]` layout
  the driver writes, this is commonly `false` because the proposer
  of an unknown-parent proposal usually isn't directly connected.
  Either way the request is fanned out as a `Forward` frame to every
  direct neighbour (issue #182) and every receiver surfaces the
  payload to its consensus dispatch — the responders look up the
  block and reply independently, the requester deduplicates by hash,
  and the wire path is the same proven one consensus broadcasts use.

#### What `rotating-failure-7n-f2` proves

Three properties end-to-end:

1. **Liveness across the faulty window.** Survivors keep committing
   while two nodes are dead — `wait --all-reach-height 15` after the
   `kill_random` step succeeds with three live nodes wedged would
   time out and fail the scenario.
2. **No false positives in safety checks.** The verifier runs over
   the union of every node's log; ANSI-tolerant `(height, view)`
   parsing means a passing run actually means consistency, not
   "grep happened to miss a colored field".
3. **Reproducibility.** Same `--seed` ⇒ same picked nodes for
   `kill_random` ⇒ identical scenario across runs. Failing scenarios
   print the seed in their error message so they can be replayed
   bit-for-bit.

#### Composing custom scenarios

For runs that the built-in subcommands don't cover, the driver also
accepts a TOML scenario file:

```toml
[scenario]
seed = 42

[[steps]]
op = "wait_all_reach_height"
height = 30

[[steps]]
op = "kill_random"
count = 2

[[steps]]
op = "wait_all_reach_height"
height = 50

[[steps]]
op = "verify_safety"
```

```sh
./target/release/testnet scenario --file my-scenario.toml --workdir testnet7
```

The available `op =` values match the CLI: `wait_all_reach_height`,
`wait_all_healthy`, `wait_quiescent`, `wait_catch_up`, `kill_random`,
`kill`, `up`, `verify_safety`. Step indices and seed are recorded in
`workdir/events.jsonl` for post-mortem analysis.

> **Why no fixed-mesh fallback in the driver.** The driver always
> writes `[overlay].mode = "gossip"` because that's the default since
> issue #137 stack 9 / commit 5b05aa3, and because the §9b sparse-ring
> layout depends on issue #178 (`RequestBlock` retry on
> `PacemakerAdvance`) and issue #182 (unicast routed through the
> gossip mesh) to converge reliably. Operators on builds that
> predate those fixes need to write configs by hand with
> `[overlay].mode = "mesh"` or a full N − 1 `[[peers]]` list — the
> driver does not paper over those older topologies.

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

For nodes you started by hand (the §1–§7 gossip walkthrough), Ctrl-C
each terminal. The binary traps `SIGINT`, drains connections (flushing
TLS `close_notify` so peers don't log an ugly unclean-shutdown error),
then exits within a few seconds.

For driver-managed clusters (§8 onwards), `testnet down` SIGTERMs every
live node, escalates to SIGKILL after a 3s grace, and reaps the per-node
`pid` files. It's idempotent — safe to run after a `Ctrl-C` interrupted
scenario, or twice in a row:

```sh
./target/release/testnet down --workdir testnet4
./target/release/testnet down --workdir testnet7
```

To reset state entirely — fresh keys, empty stores — remove the testnet
directories:

```sh
rm -rf testnet testnet4 testnet7
```

Node IDs will change after this. The driver mints fresh ones on the
next `testnet new`; for the manual gossip walkthrough, remember to
re-wire each `[[peers]]` block after re-running `ambros-p2p init`.

---

## 11. Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `/peers` returns `[]` on every node | One or more `[[peers]].node_id` values don't match the actual node IDs (typo or stale copy). Re-check the printed `node ID: ...` lines. |
| `Address already in use` on start | Something else is bound to the P2P or API port. Edit `listen_addr` to use another port, or kill the stale process. |
| Messages don't propagate | Mesh isn't formed — check `/peers` first. If peers are present but `/messages` diverges, check clocks: `expiry` comparisons use wall-clock time, and a very skewed laptop clock can make messages land already-expired. |
| `no node key found via the '<backend>' backend` | The configured key backend is empty — run `ambros-p2p init --config <path>` (file/encrypted-file) or provision the key out-of-band (env/exec/keyring) before retrying `start`. |
| `refusing to start in production without an explicit [node.identity]` | You set `AMBROS_ENV=production` or passed `--production`. For a laptop testnet, unset both and let the default file backend kick in. |
| `[node.validator_identity] is unset — reusing the network identity for consensus signing` | Single-key fallback warning. Add a `[node.validator_identity]` table to silence it; or ignore it for laptop testnets (the fallback works as it always has). |
| `validator pubkey differs from network pubkey — consensus dispatch routes messages by validator pubkey ...` | You set a `[node.validator_identity]` whose key bytes resolve to a different Ed25519 pubkey than the network key. Cross-pubkey routing requires validator-set reconfiguration (#140); until that lands, point both slots at the same key bytes (different backends are fine). |
| Consensus nodes never commit | The committees don't match. Every replica's `[consensus].validators` list must be the exact same strings in the exact same order, and `genesis_seed_hex` must be identical. Check `/consensus/status` on every node — divergent `validator_set` arrays are the smoking gun. |
| Consensus committing in steady state then stalls | A node went down and the cluster dropped below quorum. With `n = 3f + 1`, you need at least `2f + 1` live to make progress. `/consensus/status` shows `peers_connected` shrinking and `timeout_buckets` accumulating without firing. |
| `/consensus/status` returns 404 | The `[consensus]` section is missing from that node's config, or the node was started without `--config`. |
| `last_committed_height` stays at 0 while `current_view` keeps rising | The cluster is forming TCs but no QC chain is reaching the 3-chain commit rule. Common causes: mismatched `validators` or `genesis_seed_hex`, or a permanent network partition among a subset. |
| A restarted node sits at an old `last_committed_height` | Block-sync is in flight; give it a few seconds. Confirm with `grep -E 'block_sync_request_emitted\|block_sync_response_received' nodeN/log`: each unknown parent should produce a request, and each response should land. On the responder side, look for `block_sync_request_received` and `gossip_send_to_dispatched` (the `BlockResponse` going back). The `RequestBlock` retry on every `PacemakerAdvance` (issue #178) covers single-probe loss; the `OverlayFrame::Forward { target, .. }` rework (issue #182) ensures the unicast actually reaches the requester via the gossip mesh. If the lagging node has been silent for tens of seconds, also check `peers_connected` and the `storage_dir` path. |

---

## Reference: commands used above

```sh
# Build (produces target/release/{ambros-p2p,testnet})
cargo build --release

# ── Manual gossip walkthrough (§3–§7) ───────────────────────────────────────
# Bootstrap a node (idempotent; mints the file/encrypted-file key,
# creates the consensus storage_dir, prints the NodeId)
./target/release/ambros-p2p init --config testnet/nodeN/config.toml

# Start a node
RUST_LOG=info ./target/release/ambros-p2p start --config testnet/nodeN/config.toml

# Print the fully-resolved config (file + defaults). `--format json |
# jq` is the field-selection escape hatch; `--raw` prints the file
# unchanged; `--path` prints just the resolved file path; `--edit`
# opens $EDITOR / $VISUAL and validates on save.
./target/release/ambros-p2p config --config testnet/nodeN/config.toml
./target/release/ambros-p2p config --config testnet/nodeN/config.toml --format json \
    | jq '.consensus.timeout_base_ms'
./target/release/ambros-p2p config --config testnet/nodeN/config.toml --path
./target/release/ambros-p2p config --config testnet/nodeN/config.toml --edit

# Print help (shows all subcommands including `key migrate`)
./target/release/ambros-p2p --help

# ── Driver-managed consensus cluster (§8 onwards) ───────────────────────────
./target/release/testnet new --nodes 4 --workdir testnet4 \
    --ambros-bin ./target/release/ambros-p2p
./target/release/testnet up            --workdir testnet4
./target/release/testnet ls            --workdir testnet4   # static topology
./target/release/testnet snap          --workdir testnet4   # live commit/view/peers
./target/release/testnet info node1    --workdir testnet4
./target/release/testnet logs node1    --workdir testnet4 --tail 80
./target/release/testnet telemetry     --workdir testnet4
./target/release/testnet verify-safety --workdir testnet4
./target/release/testnet kill node2    --workdir testnet4
./target/release/testnet up   node2    --workdir testnet4
./target/release/testnet wait --node node2 --catch-up-to-cluster --tolerance 2 \
    --workdir testnet4
./target/release/testnet scenario rotating-failure-7n-f2 --seed 1 \
    --workdir testnet7 --ambros-bin ./target/release/ambros-p2p
./target/release/testnet down          --workdir testnet4

# ── Admin API — gossip-only fields ──────────────────────────────────────────
curl -s http://127.0.0.1:8000/peers
curl -s http://127.0.0.1:8000/messages
curl -s -X POST http://127.0.0.1:8000/messages \
     -H 'content-type: application/json' \
     -d '{"content":"hi","expiry":"<RFC3339 timestamp>"}'
curl -s -X POST http://127.0.0.1:8000/rpc/ping/<peer-node-id> \
     -H 'content-type: application/json' \
     -d '{"payload":"ping"}'

# ── Admin API — consensus (only when [consensus] is enabled) ────────────────
curl -s http://127.0.0.1:8000/consensus/status | jq

# ── Cluster sizing ──────────────────────────────────────────────────────────
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
