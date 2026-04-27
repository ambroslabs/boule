# Storage durability audit

This doc audits the on-disk storage layer (`src/storage/disk.rs`) under the
failure modes that the HotStuff persist-before-send invariant ultimately
depends on. Companion to issue [#136][issue-136]; sibling audit on the
consensus side is [#197][issue-197] (same persist chain, viewed from
re-init rather than from the disk).

The TL;DR for an operator: the node fails *loudly* on disk problems —
ENOSPC, corruption, and crashes mid-write all manifest as the consensus
loop returning an error, which terminates the node. There is no silent
loss path on the persist-before-send chain. The two known limits are
(a) redb does not verify per-page checksums on normal reads (only during
explicit `check_integrity` or on the post-crash repair scan), so a flipped
data byte may surface as a malformed payload at the consensus layer rather
than as a clean storage error, and (b) the operator runbook below is the
manual recovery procedure — there is no automatic state-sync from peers
yet (tracked separately).

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
| Page checksum (on-read)       | **Not validated by default**                   | `verify_checksum_helper` is only called from explicit `check_integrity` and the repair scan     |
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
- **Read-time checksum verification.** redb writes per-page xxhash3
  checksums but only verifies them during the post-crash repair scan
  and the explicit `Database::check_integrity` call. We do not call
  `check_integrity` on open. The reasoning: it's a full file scan, and
  the consensus layer signs every block and every QC, so a bit-flipped
  payload that survives the page checksum will fail signature/hash
  validation at the protocol layer — fail-loud, just one layer up.
  *Caveat:* this is a noisier failure mode (decode error rather than
  storage error). Tracked as a follow-up — see "Known gaps" below.

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
- A flipped byte deep inside a *payload data page* is **not always
  caught by redb on read** — see "Known gaps" below.

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

1. **redb does not verify page checksums on normal reads.** A flipped
   byte in a payload data page will not raise a storage-layer error —
   the consensus layer catches it later via its own
   signature/hash validation, but the failure mode is "decode error from
   a peer-looking message" rather than "storage corruption detected".
   The fix is one of: (a) call `Database::check_integrity()` on open
   (full file scan, slow on large WALs), (b) wrap each WAL entry with
   our own CRC, or (c) lobby upstream redb to add an opt-in
   read-time-verify mode. Tracked as [#233][issue-233].

2. **No automatic peer state-sync on a corrupt WAL.** The current
   recovery procedure is "restore from a backup or wipe and re-join the
   cluster". Eventually a node should be able to detect "my WAL is
   unrecoverable" and request a snapshot from peers; that's mentioned
   in the issue but is out of scope for this audit. Tracked as the
   block/state-sync work — see [#136][issue-136] body for the pointer.

3. **Hand-truncated files panic instead of returning `Err`.** Functionally
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

[issue-136]: https://github.com/zrbecker/ambros-p2p/issues/136
[issue-197]: https://github.com/zrbecker/ambros-p2p/issues/197
[issue-233]: https://github.com/zrbecker/ambros-p2p/issues/233
