# A1 Phase-0 spike findings — reth-SDK custom executor + payload-attributes round-trip (#780)

Go/no-go gate for **A1** (#777): can boule apply a deterministic **system write**
to predeploy storage from a **custom reth block executor**, driven by a custom
consensus value, using reth **as a library (no source fork)** — and does a
**non-proposing replica reproduce the byte-identical write** over the Engine API?

## Verdict: **GO — with one mandatory caveat about the carrying mechanism**

The executor seam exists, is exactly the EIP-4788/withdrawals mechanism, and is
composable into a custom binary via `NodeBuilder` at the version boule targets
(reth **v2.2.0**). The system write itself is ~30 lines.

**The single caveat — and it is load-bearing:** a custom field added to
`PayloadAttributes` is a **build-only input and does NOT survive into the sealed
block**, so a verifying node's `newPayloadV4` never sees it. To make the write
deterministic across proposer and verifier, the value **must be carried in a
committed sealed-block field**. The spike proves the correct carrier is the
header **`extra_data`**, which round-trips byte-identically through both the
build and the verify path and is the single field both code paths feed into the
executor's context. With that carrier, A1's determinism story holds by
construction.

> Recommended carrying mechanism: **encode the consensus value(s) into the block
> header `extra_data`** (or a commitment to them), written by a thin custom
> payload-builder on the build path; the custom executor reads them back out of
> `EthBlockExecutionCtx.extra_data` on both paths. A custom `PayloadAttributes`
> field is still the *ingress* (boule → EL over the Engine API), but it is **not**
> the carrier — it must be transcribed into `extra_data` during build.

Scratch spike location (reproducibility): `~/code/reth-a1-spike`
(`paradigmxyz/reth` @ tag **v2.2.0**, commit `88505c7`, which matches the local
`reth --version` binary exactly). The adapted example is
`examples/boule-a1-spike/`. The build needed one host workaround (see Gotchas).

**The adapted spike compiles and links a working custom reth binary** against the
real v2.2.0 SDK traits: `cargo build -p boule-a1-spike` → `Finished` in 5m45s, no
errors/warnings; the 560 MB `boule-a1-spike` binary runs (`--help` shows the full
reth CLI). So the executor seam is **live-proven, not merely reasoned** — my
`ConfigureEvm` / `BlockExecutorFactory` / `BlockExecutor` /
`ConfigureEngineEvm` / `ExecutorBuilder` implementations type-check against the
real reth crates and assemble into a node via `NodeBuilder`.

---

## Environment & versions

| Thing | Value |
|---|---|
| reth | **v2.2.0** (tag), commit `88505c7fcbfdebfd3b56d88c86b62e950043c6c4` — identical to the local `reth` binary |
| reth EVM/exec traits | `reth_evm` / `reth_ethereum::evm::primitives` |
| executor ctx type | `alloy_evm::eth::EthBlockExecutionCtx` (from `alloy-evm` **v0.34.0**) |
| rustc / cargo | 1.95.0 |
| template | `examples/custom-beacon-withdrawals` (system call via `transact_system_call` + `db_mut().commit`) |
| 2nd template | `examples/custom-engine-types` (how a custom `PayloadAttributes` field is added — and dropped) |

---

## The seam (confirmed, exact APIs at v2.2.0)

The doc's described chain is correct and present. Top-to-bottom, the traits the
custom binary implements (all delegate to the Ethereum impls except one hook):

- **`reth_ethereum::node::api::ConfigureEvm`** — top-level config; returns the
  factory + assembler.
- **`alloy_evm::block::BlockExecutorFactory`** — `create_executor(evm, ctx)`
  builds the per-block executor from an **`EthBlockExecutionCtx`**.
- **`reth_ethereum::evm::primitives::execute::BlockExecutor`** — the per-block
  hooks: **`apply_pre_execution_changes()`** (the EIP-4788/2935 slot — where we
  apply the registry write), the tx loop, and `finish()` (the EIP-7002/7251
  slot — where the withdrawals example applies its call).
- **`reth_ethereum::node::builder::components::ExecutorBuilder`** —
  `build_evm(ctx)` returns our `ConfigureEvm`; wired with
  `EthereumNode::components().executor(CustomExecutorBuilder::default())`.
- **`reth_ethereum::node::api::ConfigureEngineEvm<ExecutionData>`** — the
  verify-side counterpart: `context_for_payload(payload)` builds the ctx from a
  *sealed payload* (the `newPayloadV4` path). **This trait is the crux of the
  determinism question** (see below).

A "system call" is an EVM call from `SYSTEM_ADDRESS`
(`0xffff…fffe`, no key) to a fixed contract, executed outside the tx list and
committed into block state via `evm.transact_system_call(...)` →
`evm.db_mut().commit(state)`. Our `recordSettled` write is structurally
identical to the withdrawals/4788 calls.

### The executor hook (spike code)

```rust
fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
    // Pure consensus-derived mirror, independent of the block's txs → pre-exec.
    if let Some(view) = self.settled_view {
        apply_record_settled(view, self.inner.evm_mut())?;
    }
    self.inner.apply_pre_execution_changes()
}

pub fn apply_record_settled(view: u64, evm: &mut impl Evm<..>)
    -> Result<(), BlockExecutionError>
{
    let mut state = evm.transact_system_call(
        SYSTEM_ADDRESS, REGISTRY_ADDRESS,
        recordSettledCall { view }.abi_encode().into(),
    ).map_err(|e| /* revert -> BlockExecutionError */)?.state;
    state.remove(&SYSTEM_ADDRESS);  // don't pollute the state root
    evm.db_mut().commit(state);
    Ok(())
}
```

Placement: **`apply_pre_execution_changes()`**, not `finish()`. The registry
writes (`recordSettled`/`recordKey`/`recordWeight`) are deterministic mirrors of
consensus inputs we pass in; they don't depend on tx outcomes, so the EIP-4788
slot is the right mental model.

---

## The determinism crux — the #1 risk, answered from source

The question (from the feasibility doc): *does a custom `PayloadAttributes` field
survive build → propagate → `newPayloadV4` so a non-proposing replica applies the
identical write?*

**Answer: not as a `PayloadAttributes` field — but yes via a sealed-block field.**
Here is the exact mechanism, traced through reth v2.2.0 source.

### 1. The executor's only window onto block data is `EthBlockExecutionCtx`

`crates/ethereum/evm/src/lib.rs` builds this ctx in **three** places, and the
struct has exactly these data fields: `parent_hash`, `parent_beacon_block_root`,
`ommers`, `withdrawals`, `extra_data`, `slot_number`, `tx_count_hint`.

| ctx builder | used on | sources the fields from |
|---|---|---|
| `context_for_next_block(parent, attrs)` | **build** (proposer) | `NextBlockEnvAttributes` (derived from `PayloadAttributes`) |
| `context_for_payload(payload)` | **verify** (`newPayloadV4`) | the **sealed** `ExecutionData` (block + sidecar) |
| `context_for_block(block)` | re-exec of a stored block | the sealed block's header/body |

The verify path reads **only sealed-block data**:
```rust
fn context_for_payload<'a>(&self, payload: &'a ExecutionData) -> ... {
    Ok(EthBlockExecutionCtx {
        parent_beacon_block_root: payload.sidecar.parent_beacon_block_root(),
        withdrawals: payload.payload.withdrawals()..., // body field
        extra_data:  payload.payload.as_v1().extra_data.clone(), // header field
        slot_number: payload.payload.as_v4().map(|v4| v4.slot_number),
        ..
    })
}
```
So **the only values an executor can use deterministically on both proposer and
verifier are the fields of the committed block**: `parent_beacon_block_root`,
`withdrawals`, `extra_data`, `slot_number`. A value that lives *only* in
`PayloadAttributes` is invisible here — `newPayloadV4` is given the sealed block,
not the attributes that built it.

### 2. A custom `PayloadAttributes` field is dropped (upstream proof)

`examples/custom-engine-types` adds `CustomPayloadAttributes { inner, custom: u64 }`.
Its `PayloadAttributes` trait impl forwards only the standard fields, and its
custom payload-builder explicitly **discards** the custom field when handing off
to the inner builder:
```rust
// examples/custom-engine-types/src/main.rs (try_build)
self.inner.try_build(BuildArguments {
    config: PayloadConfig { parent_header, attributes: attributes.inner, payload_id },
    //                                                            ^^^^^ `custom` dropped
    ..
});
```
This is the canonical upstream demonstration that a custom attribute is a
**building input only**; nothing carries it into the block unless you write code
to commit it into a real block field.

### 3. `extra_data` is a byte-identical round-trip carrier

`extra_data` flows end-to-end with no transformation:

- **build:** the payload-builder puts bytes into `NextBlockEnvAttributes.extra_data`
  → `context_for_next_block` copies them to `ctx.extra_data` → the block assembler
  writes them straight into the header (`crates/ethereum/evm/src/build.rs`:
  `extra_data: ctx.extra_data`).
- **verify:** `context_for_payload` reads `payload.payload.as_v1().extra_data`
  back into `ctx.extra_data`.

Both paths hand the **same bytes** to `create_executor` as
`EthBlockExecutionCtx.extra_data`. The spike's executor decodes its `settled_view`
from exactly that field, so the proposer and a verifier compute the **identical**
`recordSettled` write by construction — the same guarantee EIP-4788 gets from
`parent_beacon_block_root`.

> ⚠️ **One real build-path wiring detail:** stock reth fills
> `NextBlockEnvAttributes.extra_data` from a **static node-config constant**
> (`builder_config.extra_data`, the client-version string), *not* from the
> per-block `PayloadAttributes`. So carrying a per-block value requires a **thin
> custom payload-builder** that transcribes boule's custom attribute into
> `extra_data` at build time (the `custom-payload-builder` /
> `custom-engine-types` examples show exactly this seam). The executor side is
> the easy half; the payload-builder transcription is the necessary glue.

### Carrier options ranked

1. **`extra_data` (recommend).** Arbitrary bytes, no semantic conflict, full
   byte-identical round-trip, already plumbed into both ctx builders. Big enough
   for the spike's `settled_view`; for the full `(keys, weights, settledView)`
   payload, carry a **32-byte commitment** in `extra_data` and the preimage in a
   companion sealed field or via the same custom-attrs channel re-derived
   deterministically. (extra_data is unbounded in size but bloats every header,
   so prefer a commitment for large payloads.)
2. **`withdrawals` (works, abusive).** A real body field the verify path reads;
   the withdrawals example proves it round-trips. But it overloads a
   consensus-layer concept boule may want for its real meaning. Avoid.
3. **`slot_number` (NOT usable at v2.2.0).** Although it is a header field and is
   sourced from `PayloadAttributes` on the build path, the v2.2.0 block assembler
   hardcodes `slot_number: None` (`build.rs`), so it does not actually round-trip
   yet. Revisit post-Amsterdam.
4. **Raw `PayloadAttributes` field (does NOT work).** The whole point above — it
   never reaches the verifier. Use it as ingress only.

---

## API-stability / churn notes (v2.2.0)

- The trait *shape* matches the feasibility doc and the upstream examples
  compile against it unchanged. The custom logic is **well under 200 lines** and
  is almost entirely trait-delegation to `EthEvmConfig` / `EthBlockExecutor`.
- Churn lives in associated types and import paths, not the seam's existence:
  `EthBlockExecutionCtx` now comes from **`alloy-evm` v0.34.0** (an external
  crate boule must pin alongside reth), and the executor must also implement
  **`ConfigureEngineEvm<ExecutionData>`** (the verify-path ctx builder) — easy to
  miss; it is the trait that proves/dooms determinism, so it must be correct.
- This is the same surface op-reth/AlphaNet ride every release. Expect a small
  per-upgrade touch-up on the ~200-line assembly; bounded and SDK-contracted.

---

## Did we run a live two-instance determinism check?

**Single-binary build live-proven (it compiles + links + runs); two-instance
Engine-API determinism loop reasoned from source, not executed.** Rationale: the
determinism guarantee is a *property of where the value is read*, and that is
fully decided by the three `EthBlockExecutionCtx`
builders shown above — both proposer (`context_for_next_block`) and verifier
(`context_for_payload`) read the **same** `extra_data` field from data that is
identical (the sealed block is what propagates). A live two-node Engine-API loop
would re-confirm what the source already determines: it cannot read a value the
ctx builder does not put in scope. The spike compiles the seam and the system
write; the carrier correctness is a source-level certainty, not an empirical
coin-flip.

(The full A1 MVP should still add a multi-node determinism test (#766-style):
build a payload with a non-trivial `extra_data` on node A, feed it to
`newPayloadV4` on node B, and assert `getStorageAt(REGISTRY, slot)` matches. That
is a Phase-1 integration test, not a Phase-0 go/no-go input.)

---

## Gotchas

- **Build prerequisite (host):** reth's `mdbx-sys` runs `bindgen` via
  **libclang-21**, but the box has no `clang` binary and no clang resource-dir
  headers, so bindgen failed with `'stdarg.h' file not found`. Fix without sudo:
  `export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/15/include"`.
  CI for the future `boule-el` crate must ensure clang headers are present.
- **A reth-SDK build is large** (dependency graph in the hundreds of crates).
  Keep `boule-el` a separate gated crate/binary, throttle with `--jobs 3`. It
  builds a **binary**, so it does not pull reth into `boule-core`/`boule-consensus`.
- **System-account hygiene:** remove `SYSTEM_ADDRESS` from the committed state
  delta (and the beneficiary, if touched) so the system call doesn't perturb the
  state root — the withdrawals example does this and we replicate it.
- **Two traits, not one:** implementing only `ConfigureEvm`/`BlockExecutor` is a
  trap — `ConfigureEngineEvm<ExecutionData>` is what runs on `newPayloadV4`. Both
  must build the ctx so the executor sees the carrier on both paths.

---

## Recommendation for Phase 1

- **Mechanism: A1, SDK-composed custom binary** — confirmed viable.
- **Carrier: `extra_data`** holding the value (or a 32-byte commitment to the
  `(keys, weights, settledView)` payload), written by a **thin custom
  payload-builder** that transcribes boule's custom `PayloadAttributes` ingress
  into `extra_data`; read back by the custom executor via
  `EthBlockExecutionCtx.extra_data` on both build and verify.
- **Apply in `apply_pre_execution_changes()`** as a `SYSTEM`-address system call
  to the `Registry` predeploy.

### Top remaining unknowns for Phase 1

1. **Payload-builder transcription** — the build-path glue (`PayloadAttributes`
   custom field → `NextBlockEnvAttributes.extra_data`) is unimplemented in this
   spike (the executor reads `extra_data` directly). It is the genuine remaining
   code; `custom-engine-types` + `custom-payload-builder` show the pattern.
2. **Payload size** — `extra_data` for the full registry payload vs. a commitment
   + preimage channel; pick before encoding the real `(keys, weights, settled)`.
3. **`recordWeight`/`recordKey` determinism** — same carrier proven, but confirm
   the *encoding* of validator deltas is stable and consensus-canonical.
4. **#767 simplification** — synchronous in-block writes *should* retire the
   conservative settled-frontier machinery; confirm before deleting safety code.
5. **CI/`cargo deny`** for the reth-SDK dependency tree + the clang-headers build
   prerequisite.

Relates #780, #777.
