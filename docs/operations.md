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

## Rotating a validator's consensus signing key (issue #142)

A validator can swap its consensus signing key without leaving and
rejoining the validator set. The protocol path lives in
`src/consensus/validator_rotation.rs` (the dual-signed tx),
`src/consensus/validator_key_history.rs` (the per-validator key
timeline), and `src/consensus/node.rs::apply_committed_rotations`
(the commit-time application). Reasons to rotate, from
[the issue][142-issue]:

- Periodic key hygiene (annual rotation policy).
- Suspected (but not confirmed) compromise — full compromise needs
  the removal path under [validator-set reconfiguration](testnet-local.md).
- Migration to a stronger backend (`file` → `keyring` → HSM).

[142-issue]: https://github.com/zrbecker/ambros-p2p/issues/142

The rotation transaction is **self-attested**: it carries two
Ed25519 signatures over the same canonical pre-image, one under the
validator's *current* consensus key and one under the proposed *new*
key. Both must verify before the rotation can take effect. Without
the dual-signature, an attacker who holds only the current key
could rotate to a key only they control, locking out the legitimate
operator.

### Producing the new key

Mint the new key under any of the existing `KeyProvider` backends
(file, env, encrypted file, exec, keyring). The choice can match or
differ from the current `validator_identity` backend — rotation is
the natural moment to migrate from a hot backend to colder
storage (`file` → keyring/HSM).

For the file backend, today, you'll generate the new keypair
out-of-band (e.g. with `openssl genpkey -algorithm Ed25519`) and
write the PKCS#8 DER bytes to a fresh path. The `key migrate`
subcommand (introduced with the split network/validator identity in
issue #141) moves an *existing* identity between backends; it does
not mint new keys.

A future CLI subcommand will wrap "mint + sign + submit" into a
single command (parallel to `reconfig add-validator` /
`reconfig remove-validator` from issue #251). Until that lands,
operators construct rotation transactions programmatically against
the `DualSignedRotation::sign` API.

### Choosing `v_eff`

`v_eff` is the view at which the new key becomes the validator's
authoritative signer. The protocol enforces a floor of
`current_view + 2` views (`V_EFF_MIN_DELAY` in
`validator_rotation.rs`); operators should pick a much larger
lead time in production:

- A few hundred views is typical — enough that the operator has
  time to provision the new key on the running node, schedule a
  restart window, and perform the restart before `v_eff`.
- **Once the rotation commits there is no abort path.** If `v_eff`
  arrives before the validator can produce votes under the new key,
  the validator is effectively offline until it catches up — same
  failure mode as a slow joiner. With `n = 4` and `f = 1` the
  cluster quorum is `3`, so the cluster keeps committing without
  the rotated validator's vote, but liveness is at its floor and
  any other transient failure (slow peer, partition) starts to bite.

### Submitting the rotation transaction

A rotation transaction is a tagged opaque payload in a
`Block.commands` slot, mirroring how `ReconfigCommand` is carried
(see [the reconfig runbook](testnet-local.md)). The on-the-wire
form is `b"VKROT\0" || postcard(DualSignedRotation)`; the
constructor is `DualSignedRotation::sign(payload, current, new)`.

Pseudocode for a one-off submission, until the wrapping CLI
subcommand lands:

```rust
use ambros_p2p::consensus::validator_rotation::{
    DualSignedRotation, ValidatorKeyRotation,
};

let payload = ValidatorKeyRotation {
    validator: <validator's currently-active pubkey>,
    new_pubkey: <new signer's pubkey>,
    v_eff: <chosen effective view>,
};
let envelope = DualSignedRotation::sign(payload, &*current_signer, &*new_signer)?;
let bytes = envelope.encode_command();
// Inject into the validator's mempool by any in-process route, or
// have a colocated peer accept it via gossip.
```

The encoded bytes can be dropped into any validator's mempool;
whichever validator is the leader of the next view picks it up,
proposes it inside a block, and the standard 3-chain commit rule
seals it. Every replica's `apply_committed_rotations` then runs
the same dual-signature check independently — no replica trusts
another's verdict.

### Provisioning the new key on the running node

Currently, the validator's signing identity is read from
`[node.validator_identity]` once at startup and bound into the
running consensus loop. Mid-run swap of the active signing key is
**not yet supported** — that requires a deeper refactor of the
`Signer` trait to decouple "claimed identity" from "active signing
key" (tracked as a follow-up to #260, since the existing trait
returns a single `node_id()`).

The operational sequence today is:

1. **Before `v_eff`** — submit the rotation transaction; observe
   that it commits.
2. **After it commits, before `v_eff`** — update the node's
   `config.toml` to point `[node.validator_identity]` at the new
   key's backend and path. Restart the node. The restart loads the
   new identity and validates against the persisted
   `validator_key_history`, which already records the rotation.
3. **At `v_eff`** — the node is now signing with the new key; other
   validators verify it through `validator_key_history.key_at(view)`,
   which returns the new pubkey for any view `>= v_eff`.

If the restart slips past `v_eff`, the validator's old-key votes are
rejected by other replicas (PR #286's three-step signer check) and
the cluster runs at f=0 (no fault tolerance) until the validator
restarts under the new key.

### Verifying the rotation took effect

The most direct observable today is the chain itself: the
`DualSignedRotation` envelope is preserved in the committed block's
`commands` and can be inspected with any block-reading tool that
filters by the `VKROT\0` tag prefix. After `v_eff`, the rotated
validator's votes carry the new pubkey as their signer field —
visible in the `Vote` envelopes flowing through the consensus
protocol (see `src/consensus/dispatch.rs`).

A future enhancement will surface the post-rotation key history in
`/consensus/status`, parallel to the validator-set boundaries
already reported there. Until that lands, log inspection
(`rotation_applied` info-level traces from
`apply_committed_rotations` on every replica) is the canonical
operator-facing signal that a rotation took effect cluster-wide.

### Failure modes

- **Rotation rejected at commit time.** Both signature checks and
  the structural floor (`v_eff >= current_view + 2`) run
  independently on every replica. A malformed rotation (single
  signature, mismatched key pair, `v_eff` too soon) is logged at
  warn level (`rotation_signature_verification_failed` /
  `rotation_history_apply_failed`) and dropped. The cluster keeps
  committing; the validator's key history is unchanged. There is no
  on-chain receipt of rejection — the `DualSignedRotation` bytes
  remain in the committed block as inert data.
- **Validator not ready by `v_eff`.** As above: the validator's
  old-key votes stop counting after `v_eff`, the cluster runs at
  reduced fault tolerance, restart resolves it.
- **Aborting a pending rotation is not supported.** Once a rotation
  commits, its `v_eff` is binding. To revert to the old key the
  operator must submit a *new* rotation transaction (signed by the
  current new key + a re-introduction of the old key as
  `new_pubkey`). The history retains every key the validator has
  ever used, so the old key is still reachable as a target.
- **Total key loss.** If both the current and the new key become
  unrecoverable, the validator cannot self-attest a further
  rotation. Recovery is the validator-set removal path: another
  validator submits a `ReconfigCommand { removes: [<validator>], …
  }` to drop the lost validator from the set, then re-adds the
  operator with a fresh identity. See
  [the reconfig runbook](testnet-local.md).

### Relationship to validator-set reconfiguration

Rotation and reconfig are independent mechanisms. The key history
is keyed by the validator's *stable identifier* (its genesis
pubkey, or — for a validator added via reconfig — the pubkey it was
added under). Reconfig adds and removes stable identifiers from the
active set; rotation changes which signing key a stable identifier
authoritatively uses, without touching set membership.

A validator added via reconfig at view `R` starts with its initial
pubkey as both stable id and signing key. It can later rotate via
the same flow described here.

## Consensus signature scheme (issues #143, #287–#296)

A chain commits to one signature scheme at genesis and uses it for
the lifetime of the chain. Two schemes are supported, each with
distinct operational tradeoffs.

### Picking a scheme

| | `ed25519_collected` | `bls_aggregated` |
|---|---|---|
| QC size on the wire | grows linearly with the quorum (~64 B per signer) | constant ~96 B aggregate + bitmap |
| QC verification cost | `O(n)` `ring::ED25519::verify` calls | one BLS pairing check |
| Validator key shape | one 32-byte Ed25519 key (also network identity) | one 32-byte Ed25519 key (network identity) **plus** a 32-byte BLS12-381 secret key |
| Operator setup | a single `[node.identity]` key, just like today | the same `[node.identity]` key **and** a separate BLS validator key file |
| Rogue-key defense at registration | not applicable (Ed25519 keys are self-authenticating) | proof-of-possession (PoP) on each `add` reconfig — the validator signs their own pubkey and the registration tx carries that signature |
| Production scale ceiling | ~150–200 validators (Cosmos-Hub regime) | thousands |
| Maturity in this codebase | shipping default | trait-level support shipped in #287–#295; full integration through the voting layer and proptest harness is the follow-up to #293 |

**When to pick which:**

- Permissioned, small-`n`, simplicity-first deployments (≤100
  validators) → `ed25519_collected`. Ed25519 is what's wired into
  the network identity and TLS layer anyway, so there's nothing
  extra to manage.
- Public networks, large-`n`, sub-second block times, or any
  deployment where per-view bandwidth is the bottleneck →
  `bls_aggregated`. Past the ~150-validator mark the linear
  growth of collected sigs starts to dominate gossip bandwidth.

The scheme is **fixed at genesis**. Switching requires a
coordinated chain restart from new genesis — same constraint as
changing the hash function or domain separators. Mixed-scheme
chains (different validators on different schemes within the same
chain) are out of scope.

### Genesis configuration

Set the `signature_scheme` field in the `[consensus]` table:

```toml
[consensus]
validators = [ "...", "...", "...", "..." ]
genesis_seed_hex = "00112233...ff"
signature_scheme = "ed25519_collected"   # or "bls_aggregated"
# … other consensus fields …
```

The default is `"ed25519_collected"`. Unknown values are rejected
at startup — an operator typo (e.g. `"ed25519_aggregated"`) fails
the parse with a message that names both the offending field and
the value.

### Validator key material

**On Ed25519 chains** the existing `[node.identity]` /
`[node.validator_identity]` slot is sufficient: one Ed25519 key
serves both network identity and consensus signing.

**On BLS chains** every validator additionally provisions a BLS
secret key. The file-backed [`BlsKeyFile` provider][bls-key-file]
generates a fresh 32-byte BLS12-381 secret key on first start and
persists it to disk with `0o600` permissions. The on-disk format
is one version byte (`0x01` today) followed by the 32 raw secret
bytes — total 33 bytes. PEM/PKCS#8 framing is unnecessary because
BLS12-381 isn't an X.509 algorithm.

The proof-of-possession (PoP) is **not** persisted alongside the
secret. It's derived from the secret on every load — keeps the
on-disk format minimal and means there's only one source of
truth.

[bls-key-file]: ../src/crypto/bls_key.rs

### Validator registration on BLS chains

Adding a validator via the `add-validator` reconfig CLI on a BLS
chain requires the new validator's BLS pubkey **and** a
proof-of-possession signature: the validator signs their own
compressed BLS pubkey under the IETF `_POP_` ciphersuite. The
reconfig validator rejects any `adds` entry whose embedded
`bls_pop` fails to verify, with a clear `BLS PoP for validator
<NodeId> failed to verify` error.

The PoP defends against rogue-key attacks: an attacker who picks
a pubkey `K' = K_target − K_self` cannot produce a valid PoP for
`K'` without holding its secret half, so the registration is
rejected pre-commit. Without PoP, BLS aggregation is vulnerable.

PoPs are not required on Ed25519 chains — Ed25519 keys are
self-authenticating, so the field is `None` on every `adds` entry.

### Historical key retention across reconfigurations

QCs from before a reconfiguration must remain verifiable forever,
so nodes retain the historical pubkey for every validator they
have ever known. On Ed25519 chains this is
[`ValidatorKeyHistory`][vkh]; on BLS chains it's the parallel
[`BlsKeyHistory`][bkh], keyed by stable Ed25519 NodeId.

Both structures answer "which pubkey was active for validator V
at view T?" via binary search on a per-validator timeline. Old
QCs verify against the era's pubkey, not the validator's current
one.

[vkh]: ../src/consensus/validator_key_history.rs
[bkh]: ../src/consensus/bls_key_history.rs

### Bandwidth/CPU benchmark

The relative cost of the two schemes is reported by an `#[ignore]`d
benchmark:

```sh
cargo test --release --test qc_scheme_bandwidth --ignored -- --nocapture
```

`--release` matters; debug builds dominate the BLS pairing check
by 100× and would mislead the comparison. Sample output and
analysis are in the bench's docstring; the headline number is
that BLS QC wire size is constant in `n` while Ed25519 grows
linearly — at `n = 200` (`q = 134`) BLS is ~55× smaller on the
wire (159 B vs 8.7 KB).
