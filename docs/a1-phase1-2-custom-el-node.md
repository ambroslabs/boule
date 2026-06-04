# A1 Phases 1+2 — custom reth EL node (EL-applied registry writes)

Implements the core of #777: a custom reth execution layer that applies boule's
registry writes (`recordKey` / `recordWeight` / `recordSettled`) as
**deterministic system calls** at the block boundary (the EIP-4788 model), fed by
a custom **`extra_data`** carrier, with **no reth source fork** (reth as a
library). Builds on the Phase-0 spike (#780/#786).

Closes the design questions in `a1-phase0-spike-findings.md` "Top remaining
unknowns": the payload-builder transcription, the encoding decision, the full
keys+weights+settled path, and the SYSTEM access-control change.

## The pipeline (end to end)

```
boule consensus → (keys, weights, settledView)            [authoritative input]
  → forkchoiceUpdatedV3(BoulePayloadAttributes{registryPayload: hex})  [ingress]
  → BoulePayloadBuilder transcribes hex into header extra_data         [build]
  → sealed block ──propagate──▶ newPayloadV4 on every replica          [verify]
  → CustomBlockExecutor decodes extra_data (same bytes both paths)      [apply]
  → SYSTEM-caller system calls to Registry predeploy storage
```

The carrier is the header **`extra_data`**: a `PayloadAttributes` custom field is
build-only and is dropped before sealing, so it can't reach a verifier; both ctx
builders (`context_for_next_block` on build, `context_for_payload` on verify)
feed `extra_data` into the executor, so the write is byte-identical on proposer
and verifier (the Phase-0 finding).

## Crate integration decision (for Phase 4 / CI)

`crates/boule-reth-node` is a **standalone workspace**, deliberately listed in
the root `Cargo.toml` `exclude`. It depends on `reth-ethereum` (and three
payload-builder crates) via a **git tag `v2.2.0`** dependency — no fork, the
AlphaNet/op-reth pattern.

Why standalone, not a workspace member:
- The reth SDK pulls hundreds of crates. Keeping `boule-reth-node` out of the
  root workspace means boule's main `cargo build` / `clippy` / `test` / `deny`
  **never resolve or compile reth** — the heavy tree and its own `Cargo.lock`
  are fully isolated. Boule's existing crates are untouched.
- The trade-off: the new crate isn't built by the default `cargo` invocation in
  the repo root; it is built from its own directory. Phase 4 wires a **separate,
  opt-in CI job** for it (own runner step, the clang-headers prerequisite, its
  own `cargo deny`), so it doesn't gate or slow boule's main matrix.

Build prerequisites (a reth-SDK binary is ~6 min + a huge dep tree):
```sh
export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/15/include"
cd crates/boule-reth-node && cargo build --jobs 3
```

## Encoding decision: (a) — full preimage in extra_data, relaxed cap

We carry the **full** `(keys, weights, settledView)` preimage directly in
`extra_data` and **relax reth's 32-byte `extra_data` cap** for boule's chain via
a custom `ConsensusBuilder` (`consensus.rs`, bounded at `MAX_EXTRA_DATA = 64 KiB`).

We did **not** use option (b) (32-byte commitment + a body-channel preimage):
validator **weight is not re-derivable from block execution** (it lives
consensus-side), so a commitment would still need a full preimage channel — and a
header field both ctx builders already plumb is strictly simpler than a system tx
the verify executor must parse out of the block body. Confirmed reth enforces the
32-byte cap in exactly one place on the verify path — `EthBeaconConsensus`'s
`validate_header_extra_data` — and it is overridable with
`with_max_extra_data_size`; the payload validator (`ensure_well_formed_payload`)
does not re-check extra_data size. So relaxing the consensus builder is the single
gate, and (a) works on a custom chain. The cost is a larger header on blocks that
carry rotations, bounded by the seated-set size.

Wire format (`registry.rs`):
```
magic "BLR1"[4] | version[1] | flags[1] | [settledView u64 BE if flag] |
keyCount u32 BE  | { validator[32] | vEff u64 BE | key[128] } * |
weightCount u32 BE | { validator[32] | weight u64 BE } *
```
`encode`/`decode` are exact inverses (round-trip + trailing-garbage + truncation
tests); a non-boule `extra_data` (e.g. stock client-version) decodes to a no-op.

## Access control: keyless SYSTEM caller (Phase 2)

`Registry.sol` now gates `recordKey` / `recordWeight` / `recordSettled` on an
`onlyWriter` modifier accepting **either** the keyless EL `SYSTEM` caller
(`0xffff…fffe`, EIP-4788 style — the new EL-applied path) **or** the legacy
`WRITER` EOA (the proposer-signed tx path). The dual-writer is transitional: the
legacy tx path is retired in Phase 3. Adding a constant + modifier does not change
the contract's storage layout, so the genesis seed is unaffected.

## Determinism evidence

- **Codec is a pure inverse** over arbitrary payloads (unit + integration tests),
  so `decode` yields the identical write set on proposer and every verifier.
- **The executor reads `extra_data` on BOTH paths** (`ConfigureEvm` build +
  `ConfigureEngineEvm` verify), from the same sealed bytes that propagate.
- The full two-instance Engine-API loop (build on A → `newPayloadV4` on B →
  `eth_getStorageAt` equal) needs two live ~560 MB nodes; deferred to a
  multi-node harness (Phase 5). The carrier correctness is a source-level
  certainty (both ctx builders read the same field), not an empirical coin-flip —
  the in-process tests pin the codec inverse and the ingress-hex → carrier-bytes
  identity.

## Remaining for Phases 3–5

- **Phase 3:** retire the proposer-signed registry tx write path
  (`boule-reth/src/registry.rs` + `application.rs`); drop `WRITER` from the
  `onlyWriter` modifier; remove the now-moot #767 conservative-frontier and
  EL-lag machinery (synchronous in-block writes make it unnecessary).
- **Phase 4:** CI — a separate opt-in job for `boule-reth-node` (clang headers,
  its own `cargo deny`), genesis with the SYSTEM caller, doc gate.
- **Phase 5:** the live two-node determinism integration test, and wire boule's
  `application.rs` build path to populate `BoulePayloadAttributes.registryPayload`
  from the real consensus `(keys, weights, settledView)` (this crate proves the EL
  side; the consensus-side population is the connecting glue).
```
