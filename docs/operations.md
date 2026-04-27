# Operations

Operational guidance for running an `ambros-p2p` validator. The
[testnet walkthrough](testnet-local.md) covers the local-cluster
driver; this document focuses on production-deployment concerns.

## Running behind NAT (issue #138)

Some operators can dial out but cannot accept new inbound TCP
connections — typically because they sit behind a corporate NAT, an
asymmetric firewall, or a cloud network with a single public load
balancer. `ambros-p2p` supports those operators through **outbound-only
mode**.

### When to use it

Set `[p2p] inbound_disabled = true` if:

- Your validator host's external IP/port is **not** reachable from the
  rest of the cluster.
- You have at least one bootstrap peer (`[overlay] bootstrap_addrs` or
  a `[[peers]]` entry) that **is** reachable. Without that, a node in
  outbound-only mode has nowhere to dial and stays orphaned.

You do **not** need this flag when:

- You run on a public IP / forwarded port — even if behind a firewall,
  if the rest of the cluster can dial you, the default
  (`inbound_disabled = false`) is correct.
- Your operator is behind NAT but can configure a stable inbound port
  via UPnP, VPN, or a tunnel — those are equivalent to inbound-capable
  hosts as far as the overlay is concerned.

### What it does

1. **Skips the TCP listener bind.** The `[node] listen_addr` field is
   still required by the parser, but no socket is opened. Other peers
   that try to dial the host get `ECONNREFUSED` (or `ETIMEDOUT` if a
   firewall silently drops the SYN).
2. **Self-advertises `reachable = false`.** The gossip overlay's
   peer-list publisher injects a self-entry with this flag, so the
   rest of the cluster learns through normal peer-list propagation
   that this node is outbound-only.
3. **Causes other nodes to skip dialing this host.** The partial-mesh
   maintenance loop on every reachable node filters its candidate pool
   to `reachable = true` peers only. Outbound-only validators are not
   counted as candidates for the maintenance-loop's "fill the deficit"
   step, so reachable nodes never waste TCP-connect attempts on hosts
   that would refuse the SYN.

The connection itself is direction-agnostic: once a TLS session is
up, both ends use it for ingress and egress. The frame multiplexer
(see `src/p2p/connection.rs`) forwards application frames to the
manager regardless of which side initiated the TCP connection. So a
node in outbound-only mode dials its bootstrap peer once, and from
that point on the connection carries consensus traffic in both
directions.

### Required configuration

Minimal example for an outbound-only validator that joins via a single
public bootstrap peer:

```toml
[node]
listen_addr = "127.0.0.1:0"   # required by the parser; no listener is bound

[node.identity]
backend = "file"
path    = "/var/lib/ambros-p2p/node.key"

[api]
listen_addr = "127.0.0.1:8000"

[p2p]
inbound_disabled = true        # outbound-only mode

[overlay]
mode             = "gossip"
bootstrap_addrs  = ["public-validator.example.org:7000"]

[consensus]
validators       = [
    "<bootstrap-validator-id>",
    "<this-validator-id>",
    "<peer-2-id>",
    "<peer-3-id>",
]
storage_dir      = "/var/lib/ambros-p2p/consensus"
```

`bootstrap_addrs` may list any reachable validator(s); the gossip
overlay uses that connection as the seed for peer-list discovery. As
soon as the bootstrap peer's peer-list gossip arrives, the
outbound-only node learns about the remaining reachable validators and
opens additional outbound connections to them, up to
`[overlay] target_degree`.

### Two-or-more outbound-only validators

If two validators are both behind NAT and both have
`inbound_disabled = true`, they cannot connect directly — neither has a
listener for the other to dial. The gossip overlay routes consensus
traffic between them through any common reachable neighbour: a unicast
`SendTo` is fanned out over the partial mesh and surfaces upstream at
every receiver, so as long as there is at least one reachable
validator that holds direct connections to both unreachable peers,
they remain in lock-step with the cluster.

This works well when ≤ ~25% of validators are outbound-only. If a
larger fraction needs NAT traversal, add hole-punching (out of scope
for this release).

### Tracking reachability across restarts

`reachable` is a sender-side claim: each node injects its own bit into
the peer-list it publishes, and the table's last-seen-wins merge
ensures that the most recent self-advertisement wins. A node that
flips between reachable and unreachable (e.g. you toggle
`inbound_disabled` and restart) propagates the new value at the next
peer-list-gossip tick (default 5 s). No coordinated config rollout is
needed.

### Verifying the deployment

The integration test
`tests/integration_test.rs::test_inbound_disabled_node_participates_via_outbound_only`
exercises this path locally without docker: it spins up a 4-node
cluster where one node has `inbound_disabled = true`, and asserts
every node — including the unreachable one — commits at steady
state. Skipping the listener bind is in fact a stronger blocker than
an iptables INPUT rule, since there is no socket to connect to at
all, and the test works identically on Linux and macOS.

## State snapshots (issue #139)

Periodic state snapshots let a fresh-joining replica catch up to the
cluster's tip without replaying every block from genesis. The
producer side (snapshot creation, retention, on-disk store) lives in
`src/consensus/node.rs::ConsensusNode::try_take_snapshot` and
`src/replication/snapshot.rs`; the joiner-side fetch state machine
lives in `src/consensus/snapshot_sync.rs`. This section is the
operator-facing summary.

### What a snapshot contains

Every `snapshot_interval_blocks` committed blocks (default
`10_000`), the leader's replica records:

- The `StateMachine::snapshot()` blob — opaque to consensus, defined
  by the application.
- The block at the snapshot height (header + commands).
- A `SnapshotManifest` (postcard-encoded) carrying:
  - schema version, height, view, block hash, state commitment,
  - the validator set active at the snapshot height,
  - per-chunk SHA-256 hashes,
  - a quorum-bearing `QuorumCertificate` over the snapshot block.

The blob is split into fixed-size chunks
(`snapshot_chunk_size_bytes`, default 1 MiB) so chunked transfer
fits under the consensus protocol's 4 MiB wire-frame cap.

A joiner that lags behind by ≥ `snapshot_interval_blocks` (compared
to the highest proposal height it has observed) starts the
snapshot-fetch path: it asks its candidate peers for the latest
manifest, verifies it against the local validator set, then fetches
chunks in parallel with sticky chunk-to-peer assignment and
per-chunk retry. After restoring state from the assembled blob, it
falls through to the existing `RequestBlock` tail-sync to fetch
blocks above the snapshot height.

### Configuration

All knobs live under `[consensus]` in the config file. Defaults are
production-sized:

```toml
[consensus]
# … other consensus fields elided …

# Take a state-machine snapshot every K committed blocks. `0`
# disables snapshot creation entirely; the joiner-side path becomes
# a no-op (fresh nodes catch up via plain block-sync).
snapshot_interval_blocks = 10000

# Number of most-recent snapshots to keep on disk. Older snapshots
# are pruned atomically when a new one commits. `0` disables
# pruning (snapshots accumulate without bound — useful for tests
# or forensic captures).
snapshot_retention_count = 3

# Bytes per snapshot chunk. Must be > 0 and leave headroom under
# the consensus protocol's 4 MiB MAX_FRAME_BYTES once the postcard
# envelope (~64 KiB reserved) is added; `Config::validate` enforces
# the bound at startup.
snapshot_chunk_size_bytes = 1048576
```

The names match `src/config.rs::ConsensusConfig` exactly. To
disable snapshots on a resource-constrained operator, set
`snapshot_interval_blocks = 0` — the rest of the consensus loop is
unaffected.

### Retention and pruning

After every new snapshot commits, the snapshot store keeps the
`snapshot_retention_count`-th newest snapshots and atomically
deletes everything older. Pruning is part of the same
`Storage::apply_batch` that writes the new manifest + chunks, so a
crash mid-prune leaves the store in a consistent state — either the
old + new snapshots are present (next prune retries), or the new
one alone is.

`snapshot_retention_count = 0` disables pruning. The store grows
without bound; useful for tests and post-mortem captures, but not
recommended on production validators.

### Disk-usage expectations

Per snapshot on disk:

```
disk_per_snapshot
    = snapshot_payload_bytes
    + manifest_size
    + per-chunk storage overhead

manifest_size
    ≈ ~250 B base (version, height, view, block hash, state
                   commitment, QC, embedded block, timestamp)
    + 32 B × num_validators                 (validator-set vec)
    + 32 B × ceil(payload / chunk_size)     (per-chunk hash list)
    + ~64 B × num_signers                   (QC signatures)

per-chunk storage overhead
    ≈ ~30 B per chunk (the redb key + framing for
                       `consensus/snap/chunk/<height_BE><idx_BE>`)
```

Total disk = `snapshot_retention_count × disk_per_snapshot`.

Two worked examples:

- **Today's reference state machine (`CounterStateMachine`, single
  `u64` counter).** Payload ≈ 1–10 bytes (postcard varint). With
  4 validators, default config:
  manifest ≈ 250 + 128 + 32 + 192 ≈ ~600 B; one chunk; per-snapshot
  ≈ ~600 B. Retention 3 → ~1.8 KiB total.
- **Hypothetical production state machine, 100 MiB payload.**
  100 chunks at 1 MiB; manifest ≈ 250 + 128 + 32×100 + QC ≈ 4 KiB;
  per-snapshot ≈ 100 MiB + 4 KiB ≈ ~100 MiB. Retention 3 → ~300 MiB.

The production state machine is currently empty (issue #24), so
today's per-snapshot disk is dominated by metadata; the math
becomes operator-relevant once the application layer lands.

### Manual export and import

`ambros-p2p` ships a CLI for hand-moving a snapshot between nodes
without running consensus. Both subcommands operate against the
`[consensus] storage_dir` configured in the node's `config.toml`
and require a `redb`-backed store at `kv.redb` (the in-memory
fallback is rejected — there's nothing to export from).

```text
ambros-p2p snapshot export [--config <path>] [--height <H>] --out <dir>
ambros-p2p snapshot import [--config <path>] --in <dir>
```

Flags:

- `--config <path>` (optional) — path to the node's `config.toml`.
  Falls back to the platform default (same as `start`/`init`).
- `--height <H>` (export only, optional) — selects an exact-height
  snapshot. Omit to export the latest.
- `--out <dir>` / `--in <dir>` — directory for the export bundle.

The bundle layout is portable across operators:

```
<dir>/
  manifest.bin           # postcard-encoded SnapshotManifest
  chunk-00000000.bin     # raw bytes of chunk 0
  chunk-00000001.bin     # raw bytes of chunk 1
  …
  chunk-NNNNNNNN.bin     # raw bytes of chunk N (zero-padded to 8 digits)
```

Filenames are pinned by `src/replication/snapshot.rs::EXPORT_MANIFEST_FILENAME`
and `export_chunk_filename`; the export/import library functions
verify schema version on read and chunk hashes on store-side
`save`, so a tampered bundle is rejected before it touches the
joiner's safety state.

#### Worked example: hand off a snapshot to a new operator

This walkthrough copies a snapshot from validator A's machine to
validator B's machine, where B has just provisioned a fresh
identity and wants to skip genesis-replay.

On A (the source):

```sh
# 1. Stop the node so the storage_dir's redb file isn't held open.
sudo systemctl stop ambros-p2p   # or whatever supervisor you use

# 2. Export the latest snapshot to a portable directory.
ambros-p2p snapshot export \
    --config /etc/ambros-p2p/config.toml \
    --out   /tmp/snapshot-bundle

# Output:
#   exported snapshot height=10000 view=10004 chunks=128 into /tmp/snapshot-bundle

# 3. Pack and ship.
tar -czf /tmp/snapshot-bundle.tgz -C /tmp snapshot-bundle
scp /tmp/snapshot-bundle.tgz operator-b@validator-b:/tmp/

# 4. Restart A.
sudo systemctl start ambros-p2p
```

On B (the destination):

```sh
# 1. Stop B's node (if running) and unpack the bundle.
sudo systemctl stop ambros-p2p
tar -xzf /tmp/snapshot-bundle.tgz -C /tmp

# 2. Import into B's local snapshot store.
ambros-p2p snapshot import \
    --config /etc/ambros-p2p/config.toml \
    --in    /tmp/snapshot-bundle

# Output:
#   imported snapshot height=10000 view=10004 chunks=128 into consensus storage

# 3. Restart. The joiner-side fetch path will detect that the
#    locally-stored snapshot already covers the cluster's height and
#    fall straight through to tail-sync for blocks above 10000.
sudo systemctl start ambros-p2p
```

Importing into a node that already has a newer snapshot at the
same height is a no-op; importing one whose validator set doesn't
match the local validator set is rejected at `manifest.verify`
time.

To export a specific historical snapshot (e.g. for forensics) pass
`--height <H>`; the CLI errors out and prints the available
heights if no snapshot exists at exactly `H`.

### Operational caveats

- **Snapshots are an optimization, not a correctness path.** A
  corrupted snapshot store, a tampered manifest, or a peer that
  serves bad chunks all surface as the joiner falling through to
  the existing `BlockRequest` tail-sync. The chain itself stays
  correct; only the catch-up speed is affected.
- **Snapshots can be disabled.** Set `snapshot_interval_blocks = 0`
  to opt out entirely. Useful on resource-constrained operators or
  during incident response.
- **Storage backend matters.** `[consensus] storage_dir` must be a
  writable path — the CLI export/import refuses to operate on
  in-memory storage (there's nothing to export from). The redb
  durability properties from the
  [storage durability audit](storage-durability.md) cover the
  snapshot tables too: `apply_batch` is fsync-on-commit, so a
  crash mid-snapshot leaves the store consistent.
- **Wire-frame budget.** Operator-tweaked
  `snapshot_chunk_size_bytes` must leave 64 KiB of headroom under
  `MAX_FRAME_BYTES` (4 MiB); `Config::validate` rejects oversize
  values at startup rather than on the first chunk.
