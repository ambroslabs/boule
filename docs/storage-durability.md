# Storage durability audit

This doc audits the on-disk storage layer (`src/storage/disk.rs`) under the
failure modes that the HotStuff persist-before-send invariant ultimately
depends on. Companion to issue [#136][issue-136]; sibling audit on the
consensus side is [#197][issue-197] (same persist chain, viewed from
re-init rather than from the disk).

The TL;DR for an operator: the node fails *loudly* on disk problems —
ENOSPC, corruption, and crashes mid-write all manifest as the consensus
loop returning an error, which terminates the node. There is no silent
loss path on the persist-before-send chain. The remaining known limit is
that the operator runbook below is the manual recovery procedure — there
is no automatic state-sync from peers yet (tracked separately).

Page-level corruption that escapes redb's per-page xxhash3 (which redb
only verifies during repair, not on every read) is now caught by two
layers of defense-in-depth: `DiskStorage::open` calls
`Database::check_integrity()` once at startup, and `DiskWal` prepends an
8-byte SHA-256-truncated checksum to every entry that
`DiskWal::iter_from` recomputes and verifies on every read. See
"Page-level corruption: read-time and open-time checks" below.

## What the persist-before-send invariant actually persists

The invariant lives in
[`apply_safety_actions`](../src/consensus/node.rs) — every
`SafetyAction::Persist` is committed to durable storage *before* any
following `SafetyAction::Broadcast` / `SendTo` / `Commit`. The committed
fields are HotStuff's safety-critical metadata: `last_voted_view`,
`locked_qc`, `high_qc`, plus the blocks those QCs reference. This goes
through `ConsensusNode::persist_updates`, which in turn calls
`Storage::apply_batch` — the only persistence path on the safety-critical
write chain.

The WAL (`Wal::append` / `Wal::flush`) is *not* on this chain today. It
exists for future log-state replay, but consensus does not read or write
it on the safety-critical path. Even so, the same audit applies because
the same redb configuration backs both — and the WAL will start carrying
safety-relevant data when block log replay lands.

## Backend choice and durability configuration

| Knob                          | Setting                                        | Source                                                                                          |
| ----------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Storage engine                | `redb` 4.1                                     | [`Cargo.toml`](../Cargo.toml)                                                                   |
| Open call                     | `Database::create(path)` — defaults everywhere | [`DiskStorage::open`](../src/storage/disk.rs), [`DiskWal::open`](../src/storage/disk.rs)        |
| Durability per commit         | `Durability::Immediate` (the redb default)     | redb's `WriteTransaction` defaults to `Immediate` — fsyncs before `commit()` returns            |
| 2-phase commit                | Off (the redb default — single-phase commit)   | See "Trade-offs" below                                                                          |
| Page checksum (on-write)      | xxhash3 over every leaf and branch page        | `redb::tree_store::btree_base::leaf_checksum` / `branch_checksum`                               |
| Page checksum (on-read)       | Not validated by redb on every read            | `verify_checksum_helper` is only called from explicit `check_integrity` and the repair scan     |
| Open-time integrity scan (KV) | `Database::check_integrity()` on every open    | [`DiskStorage::open`](../src/storage/disk.rs) — full-file xxhash3 walk, cheap because KV is small |
| Per-entry checksum (WAL)      | 8-byte SHA-256 prefix on every entry           | [`DiskWal::flush`](../src/storage/disk.rs) writes it, [`DiskWal::iter_from`](../src/storage/disk.rs) verifies it |
| File grow strategy            | redb manages — initial layout ~1 MiB usable    | `MIN_DESIRED_USABLE_BYTES = 1 MiB` in redb's `page_manager.rs`                                  |
| `Storage::apply_batch` fsync  | One fsync per `commit` call                    | `DiskStorage::apply_batch` → `txn.commit()`                                                     |
| `Storage::compare_and_swap`   | Mismatch path skips commit (no fsync)          | [`DiskStorage::compare_and_swap`](../src/storage/disk.rs) — returns `Ok(false)` before committing |
| `Wal::append`                 | In-memory buffer only (no I/O, no fsync)       | [`DiskWal::append`](../src/storage/disk.rs)                                                     |
| `Wal::flush`                  | One fsync per call (only durability barrier)   | [`DiskWal::flush`](../src/storage/disk.rs)                                                      |

### Trade-offs we did NOT pick (and why)

- **2-phase commit.** redb has it; we don't enable it. 2-phase doubles
  the fsync cost on the hot path (every `Storage::apply_batch` becomes
  two fsyncs instead of one). The mitigation it offers is against an
  attacker-controlled crash sequence with adversarial workload — see the
  threat model in `redb::WriteTransaction::set_two_phase_commit`'s docs.
  We are not in that threat model.
- **Read-time page-checksum verification across the entire WAL on every
  open.** We considered calling `Database::check_integrity()` on
  `DiskWal::open` but rejected it because it's a full file scan; on a
  multi-GB WAL the cost would dominate startup. Instead we prepend a
  per-entry SHA-256-truncated checksum to every flushed WAL entry and
  verify it on read — see "Page-level corruption: read-time and
  open-time checks" below. The KV file gets the full
  `check_integrity()` scan because its size is bounded by HotStuff's
  control-plane state (a small fixed set of keys plus the blocks the
  active QCs reference).

## Failure-mode audit

### Disk-full / ENOSPC / EFBIG

Tested in
[`storage::disk::tests::wal_disk_full_returns_error_and_preserves_durable_prefix`](../src/storage/disk.rs)
and
[`storage::disk::tests::storage_disk_full_returns_error_for_apply_batch`](../src/storage/disk.rs).
Each test spawns a child process that sets `RLIMIT_FSIZE` and ignores
`SIGXFSZ`, so writes that exceed the limit return EFBIG to userspace
rather than killing the process.

**Behavior:**
- `Wal::flush` and `Storage::apply_batch` propagate the underlying
  `io::Error` as `anyhow::Error`.
- Every `flush` / `apply_batch` that returned `Ok` is durable — the
  recovered prefix exactly matches the marker the child wrote after each
  successful commit.
- The error propagates up through `apply_safety_actions` → `apply_dispatch`
  → `ConsensusNode::run` → the consensus task terminates. The node exits.
  There is no silent retry, no acked-but-not-persisted state.

**Operator action:** the node will exit non-zero with the I/O error in
its logs. Restore disk capacity and restart; the durable prefix on disk
is correct and consensus will resume from it.

### SIGKILL / `abort()` mid-write (crash safety)

Tested in
[`storage::disk::tests::wal_opens_cleanly_after_sigkill_during_writes`](../src/storage/disk.rs)
plus the four pre-existing `*_durable_across_crash` tests that use
`std::process::abort()`.

**Behavior:**
- The redb single-phase commit protocol writes the new state to the
  inactive commit slot, then atomically flips the god-byte to point at
  it, then fsyncs. A crash before the god-byte flip leaves the previous
  slot live; a crash after the flip means the new slot is durable.
- `DiskWal::open` and `DiskStorage::open` succeed cleanly after a
  SIGKILL during a flush. Recovered LSNs form a contiguous prefix
  starting at 1; the prefix length is at least the last marker the
  child wrote and may be one greater (if the kernel completed the
  god-byte flip after the marker write).

**Operator action:** none. The next start recovers the last fully-
committed state automatically.

### Corruption (bit flip / overwrite)

Tested in
[`storage::disk::tests::wal_open_rejects_garbled_header`](../src/storage/disk.rs)
and
[`storage::disk::tests::wal_open_after_random_garbage_overwrite_does_not_silently_succeed`](../src/storage/disk.rs).

**Behavior:**
- A flipped byte in the redb file *header* (offset 0 — magic number,
  layout descriptor, god-byte) causes `DiskWal::open` to fail with an
  error or panic. Either way, the node refuses to start. No silent
  recovery to a wrong state.
- A full-file overwrite with garbage is rejected at open for the same
  reason (magic-number mismatch).
- A flipped byte deep inside a *payload data page* is **not caught by
  redb on read** — but it now is by the layer we own. See
  "Page-level corruption: read-time and open-time checks" below.

**Operator action:** see [Operator runbook](#operator-runbook).

### Page-level corruption: read-time and open-time checks

redb writes a per-page xxhash3 on commit but does not verify it on
normal reads — the verification path runs only during the post-crash
repair scan and the explicit `Database::check_integrity()` call. Without
the mitigations below, a bit flip deep inside a payload data page (e.g.
from a bad sector that the OS / filesystem still hands back) would
round-trip through `Storage::get` / `Wal::iter_from` and surface
later as a malformed-message decode error at the consensus layer — fail-
loud (every block and QC is signed and hash-chained), but a confusing
diagnostic.

We close that gap from both sides:

- **KV file** ([`DiskStorage::open`](../src/storage/disk.rs)). Calls
  `Database::check_integrity()` once on every open. This is a full
  page-checksum walk of the file. We can afford it because the KV file
  is bounded by HotStuff's control-plane state — `last_voted_view`,
  `locked_qc`, `high_qc`, plus the blocks those QCs reference (only
  the active tip is needed for safety; older blocks beyond a snapshot
  watermark can be pruned). The
  [`bench_check_integrity_open_cost`](../src/storage/disk.rs)
  benchmark (release build, Apple M-series, redb 4.1, in-tree
  `#[ignore]`d test) measured the scan at ~20 ms for a fresh DB,
  ~23 ms for 1 000 1-KiB blocks (~2.7 MB file), and ~34 ms for 10 000
  blocks (~21 MB file). That's a couple of orders of magnitude below
  the existing TLS handshake / peer-discovery startup cost and well
  bounded by the small KV size. Tested by
  [`storage_open_check_integrity_detects_payload_page_corruption`](../src/storage/disk.rs).
- **WAL file** ([`DiskWal::flush`](../src/storage/disk.rs) /
  [`DiskWal::iter_from`](../src/storage/disk.rs)). Each flushed entry
  is stored as `[checksum:8][payload]` where the checksum is the first
  8 bytes of `SHA-256(payload)`. `iter_from` recomputes and verifies
  it on every read. We do *not* call `check_integrity()` on WAL open
  because the WAL is unbounded in size (one entry per consensus
  decision, plus block log replay when that lands), so a startup-time
  full-file scan would not amortize. The per-read verification covers
  the same gap and scales with the entries the caller actually reads.
  Tested by
  [`wal_iter_detects_byte_flip_inside_payload_data_page`](../src/storage/disk.rs).

The SHA-256 truncation is overkill for tamper detection (we are
guarding against bit flips on local disk, not adversarial collisions),
but `sha2` is already a dependency and the per-entry overhead is ~1 µs
on modern hardware — comfortably below the consensus per-step budget.

**Operator action:** the node refuses to start (KV) or fails when
consensus replays the WAL (per-entry checksum). Either way, see
[Operator runbook](#operator-runbook).

### Persisted validator-history blob diverges from the committed chain

Tested in
[`verify_persisted_history_consistency_rejects_byte_flip_in_v_eff`](../src/consensus/node/mod.rs),
[`verify_persisted_history_consistency_rejects_extra_boundary`](../src/consensus/node/mod.rs),
and
[`verify_persisted_history_consistency_rejects_tampered_genesis_member`](../src/consensus/node/mod.rs).

At startup, [`ConsensusNode::verify_persisted_history_consistency`](../src/consensus/node/persistence.rs)
walks every committed block from genesis to `last_committed_hash`
and rebuilds the `(validator_history, validator_key_history,
bls_key_history?)` triple from each block's reconfig and rotation
commands. It asserts that (a) each block's stamped
`validator_history_commitment` matches the rebuilt triple at that
point in the walk, and (b) the loaded persisted blobs equal the
end-of-walk rebuilt blobs byte-for-byte. Either check failing
means the persisted blob no longer matches the committed chain —
realistic causes are disk bit-flip, partial-fsync on a non-
conforming filesystem, manual restore from a stale backup or
partial state copy across hosts, or deliberate tampering.

**Behavior:** the check returns `Err` (no panic), the error chains
back through `node::run` → `handle_start` → `main`, and `main`
prints `error: verifying persisted validator histories against
committed chain (#325 PR B): <discriminating message>` and exits
non-zero. No consensus signing happens against the divergent
state. Audit finding L4-2 / issue [#504][issue-504]; the
engineering work landed in [#325 PR B][issue-325].

**Operator action:** see [Operator runbook](#operator-runbook).

### Truncated tail (e.g. partial write of a torn page)

Implicit in the SIGKILL test (the only realistic way to produce a torn
file in production) and discussed in "Known gaps" below for the
hand-crafted truncation case.

**Behavior on a real crash:** redb's god-byte protocol guarantees that
either the previous slot or the new slot is fully written, so a torn
mid-flush write rolls back to the previous slot on next open. No
truncation is needed by hand.

**Behavior on a hand-crafted truncation:** redb panics during open if
the on-disk file is shorter than what the layout descriptor claims. This
is fail-loud (the node refuses to start) but rougher than an
`Err(Corrupted)` return. Documented as "abort and refuse to start"; the
operator runbook covers it.

## Known gaps

These are real limitations the audit surfaced; each is small enough that
fixing it is plausible inline but large enough that it deserves its own
issue rather than bundling here.

1. **No automatic peer state-sync on a corrupt WAL.** The current
   recovery procedure is "restore from a backup or wipe and re-join the
   cluster". Eventually a node should be able to detect "my WAL is
   unrecoverable" and request a snapshot from peers; that's mentioned
   in the issue but is out of scope for this audit. Tracked as the
   block/state-sync work — see [#136][issue-136] body for the pointer.

2. **Hand-truncated files panic instead of returning `Err`.** Functionally
   fail-loud (the node exits and refuses to start), but uglier than an
   `Err(Corrupted)`. We don't expect this to happen in practice —
   the only realistic way to get a torn file is a crash mid-write, and
   redb handles that without truncation via the god-byte protocol — but
   if it ever does, the operator sees a panic instead of a clean error.

## Operator runbook

### "Node won't start: WAL is corrupt"

Symptoms in logs (any of):

- `consensus: durable storage at <path>` followed shortly by an exit
  with `Database::create` returning `Err(...)` — explicit corruption
  detection.
- A panic with `assertion failed: storage.raw_file_len()? >= header.layout().len()`
  — the file is shorter than its layout claims (hand-truncated, or a
  filesystem-level corruption that didn't preserve the layout invariant).
- A panic during open mentioning `magic number` or `checksum`.

What to do:

1. **Stop the node** (it's already exited, but make sure systemd /
   supervisor isn't restart-looping it).
2. **Take a copy of the broken files** — both `kv.redb` and
   `wal.redb` from the configured `storage_dir`. They're useful for
   post-mortem.
3. **Choose a recovery path:**
   - **(preferred)** Restore from a recent backup of the same
     `storage_dir`, then start the node. It will catch up to the
     cluster's tip via block-sync (which is implemented).
   - **(fallback)** Wipe `storage_dir` entirely. The node will start as
     a fresh replica. This is safe — it sacrifices the local state but
     the cluster as a whole has the safety-critical data — *as long as*
     this is a single-node failure: a quorum of peers must still be
     alive and uncorrupted. If the corruption is cluster-wide (e.g. a
     bad release or a shared-storage incident), restore from backup
     instead; never wipe more than one node at a time without
     coordinating.
4. **Restart the node.** Watch for `consensus_resumed` in logs to
   confirm a clean start, and for the height advancing to confirm
   block-sync caught it up.

### "Node won't start: validator history is inconsistent with the committed chain"

Symptoms in logs: the wrapped-context prefix
`verifying persisted validator histories against committed chain (#325 PR B)`
followed by one of the discriminating error messages from
[`verify_persisted_history_consistency`](../src/consensus/node/persistence.rs):

- `validator_history_commitment mismatch at block height=<H> view=<V>
  hash=<hex>: block claims <hex> but rebuild from chain produces
  <hex>` — a per-block check failed; the named block's stamped
  commitment doesn't match the triple rebuilt from the chain walk
  up to that point.
- `validator_history_rebuild_mismatch: loaded validator_history does
  not match rebuild from chain` — the persisted set-history blob
  diverges at end-of-walk.
- `validator_key_history_rebuild_mismatch: ...` — same, for the
  key-history blob.
- `bls_key_history_rebuild_mismatch: ...` — same, for the BLS
  key-history blob (BLS chains only).
- `validator history rebuild: walked-chain genesis hash <hex> does
  not match configured genesis hash <hex>` — the persisted block
  store's genesis differs from this node's configured genesis (the
  block store may be from a different chain entirely).

What to do:

1. **Stop the node** (it's already exited; ensure systemd /
   supervisor isn't restart-looping it).
2. **Take a copy of the broken `storage_dir`** — useful for
   post-mortem to identify the divergent boundary.
3. **Choose a recovery path:**
   - **(preferred)** Restore `storage_dir` from a recent backup,
     then start the node. It will catch up to the cluster's tip
     via block-sync.
   - **(fallback)** Wipe `storage_dir` entirely and re-join as a
     fresh replica. Same caveats as the WAL-corrupt case: only
     when a quorum of peers is alive and uncorrupted; never wipe
     more than one node at a time without coordinating.
4. **Restart the node.** Watch for `consensus_resumed` in logs and
   for the height advancing to confirm block-sync caught it up.

**Do not edit the persisted blobs by hand to "make the check
pass."** The divergence is the symptom, not the disease. Bypassing
the gate leaves the cluster signing against state inconsistent with
the committed chain — exactly the failure mode the gate prevents.

### "Node exits with `No space left on device` / `File too large`"

The node fail-stopped because a `Storage::apply_batch` or `Wal::flush`
returned an I/O error. The on-disk state is consistent — every commit
that returned `Ok` is durable; the failed commit had no effect.

1. Free disk space (rotate logs, remove temp files, expand the volume).
2. Restart the node. It resumes from the last successful commit.

No data restoration needed.

### "Node exits during normal operation with a storage error"

Same general procedure as ENOSPC: the node is fail-stop on any
`Storage` / `Wal` error, and the persisted state is consistent. Inspect
the error in the logs to identify the underlying cause (filesystem
unmounted, permissions changed, hardware fault), fix it, and restart.

[issue-136]: https://github.com/ambroslabs/ambros-p2p/issues/136
[issue-197]: https://github.com/ambroslabs/ambros-p2p/issues/197
[issue-325]: https://github.com/ambroslabs/ambros-p2p/issues/325
[issue-504]: https://github.com/ambroslabs/ambros-p2p/issues/504
