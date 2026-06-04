# Validator registry in EVM state + the slashing precompile (#732)

Design notes for milestone #4's deepest piece. Two coupled parts:

- **(a) Validator registry** — the validator **key history** materialised into
  EVM-readable storage, so EVM-side logic can answer *"which consensus key did
  validator X sign under at view V?"*.
- **(b) Slashing precompile** — a Solidity predeploy that verifies a BLS
  equivocation proof (via the **EIP-2537** precompiles unlocked by the Prague
  bump) against the registry's settled history, and slashes — moving evidence
  **verify + slash** onto the execution layer.

Tracking: #726 / #732. Prereqs landed/landing: the rotation predeploy (#730),
the Prague bump (#740, droplet-finalised). Relates #656/#657/#658 (the
consensus-side evidence path, which stays the default until this lands), #685.

## The load-bearing insight

Every validator key change **already flows through the EVM.** A signing- or
BLS-key rotation is submitted to the rotation predeploy (#730); consensus reads
it back from the committed block and applies it to its
[`BlsKeyHistory`](../crates/boule-consensus/src/bls_key_history.rs) /
[`ValidatorKeyHistory`](../crates/boule-consensus/src/validator_key_history.rs).
So the EVM is *already the submission point* for the very data the registry must
hold.

That means the registry does **not** require consensus to push state into the
EVM. If the rotation predeploy (and a small genesis seed) **store** the key
history in EVM storage — not just emit it as an event — then the EVM registry
and consensus's key history are **derived from the same submissions** and are
**consistent by construction**. This is what makes a *mirror* tractable.

## Mirror, not inversion

The issue's phrasing — *"the predeploy owns the registry and consensus derives
its live cache from it"* — describes an **inversion** (the EVM becomes the
source of truth for the validator set). We recommend **against** it for the
first (and likely every) iteration:

- **Chicken-and-egg.** To process the EVM block that contains a registry update,
  every replica must already know the validator set (to validate the block's QC
  and ordering). If the set is *derived from* the EVM, there is a circular
  dependency at exactly the safety-critical boundary.
- **Safety surface.** Inversion makes BFT safety depend on EVM execution
  correctness and the EL's availability. The deferred-execution model
  deliberately keeps the safety core independent of payload validity; inversion
  breaks that.
- **Recovery + genesis.** The genesis set and crash recovery would have to
  bootstrap from EVM state rather than the committed command log.

A **mirror** keeps consensus authoritative (exactly as today) and treats the EVM
registry as a materialised, queryable **copy** that EVM-side consumers read. It
delivers everything (a) and (b) need — historical key lookups, a slashing
read-surface — without touching consensus's authority. **Recommendation:
mirror.**

## (a) The registry mechanism

A `Registry` predeploy holds, in EVM **storage** (so a precompile can `SLOAD`
it, not just filter logs):

```
validator (bytes32 stable id) -> list of (v_eff: uint64, blsPubKey: bytes48)
```

i.e. the same shape as `BlsKeyHistory`: per-validator, the BLS pubkey active
from each `v_eff` onward. Reads:

- `keyAt(bytes32 validator, uint64 view) -> bytes48` — the BLS pubkey whose
  `v_eff <= view` is greatest (the settled historical lookup).

Writes (mirror population), **fork-free**, no consensus→EVM push:

1. **Genesis seed.** The genesis validators' BLS pubkeys are written into the
   `Registry` predeploy's **genesis storage** (`alloc[Registry].storage`), the
   EVM analogue of `BlsKeyHistory::with_genesis`. (Storage-slot layout is part
   of the build; the genesis-pin test ties it to the genesis artifact, like the
   predeploy bytecode pins today.)
2. **Rotations.** The rotation predeploy (#730) is extended so that, in addition
   to emitting `RotationSubmitted`, it **records** the rotation in `Registry`
   storage: append `(v_eff, newBlsPubKey)` to the validator's history. Because
   consensus reads the *same* submission to drive its own `BlsKeyHistory`, the
   two never diverge. (Alternatively a dedicated `Registry.recordRotation` the
   rotation flow calls — an implementation detail.)
3. **Reconfig adds/removes.** An add seeds the new validator's genesis-equivalent
   entry; a remove may tombstone it (but history is retained — slashing can
   target a since-removed validator for a past-view equivocation).

No consensus-side code writes EVM state; the registry is a pure function of the
EVM submissions consensus already consumes.

## The consistency / lag contract

The registry is updated when a rotation **tx executes** — which is *before* its
`v_eff` (rotations are future-dated to clear the execution lag, #730). So:

- **Live path** (*"which key is active right now?"*) — the registry may hold a
  future-dated rotation not yet active, or lag the consensus head by the
  execution delay. **This path stays consensus-native** (per #726: live signer
  verification is irreducible). The registry is *not* consulted for live
  verification.
- **Settled / historical path** (*"which key was active at past view V?"*) —
  once the chain has progressed past `V` **and** the registry has recorded every
  rotation with `v_eff <= V`, the answer is **settled and lag-free**. The
  execution lag is bounded; an equivocation `view` is in the past by the time a
  proof is submitted (detection → evidence → submission all follow it), so the
  registry has caught up.

**The contract:** the slashing precompile accepts a proof for view `V` only when
`V <= settledFrontier` — the highest view all of whose rotations the registry has
recorded. That frontier is itself derivable in-EVM (the registry knows the EVM
block height; consensus's executed-frontier maps to it 1:1, the #674 invariant).
Below the frontier, `keyAt` is authoritative; at/above it, the precompile
rejects (the watcher resubmits once it settles). This is exactly the boundary
#726 names: **historical key state is settled, so verification can move to the
EL; only the live path can't.**

## (b) The slashing precompile (what (a) enables)

A `Slashing` predeploy, on a **Prague** chain (so EIP-2537 BLS12-381 precompiles
exist) with **BLS-scheme** validators (so proofs are BLS sigs):

1. A watcher submits an equivocation proof as calldata: `(validator, view, blockHashA, sigA, blockHashB, sigB)`.
2. The predeploy checks `view <= settledFrontier`, `blockHashA != blockHashB`
   (same view, different block = equivocation), then reads
   `blsKey = Registry.keyAt(validator, view)`.
3. It verifies `sigA` and `sigB` under `blsKey` over the canonical pre-images,
   via the EIP-2537 pairing precompile.
4. On success it **slashes** — reduces the validator's bonded stake in the
   `Staking` contract's storage — and emits `Slashed(validator, view)`.
5. boule reads `Slashed` like any predeploy event (the #655/#730 pattern) and
   applies the weight reduction through its `StakeSource` → `validator_updates`
   → jail reconfig (the existing #658 apply-target).

This moves evidence **verify + slash** into the EL. It is **optional**: PoA
chains skip slashing entirely; Ed25519-scheme chains can't use it (Ed25519 is
not an EVM precompile — only BLS verification is in-EVM-feasible), and fall back
to the consensus-side #656/#657/#658 path, which remains the default.

## What stays consensus-native (per #726)

Irreducible, regardless of (a)/(b):

- **Equivocation detection on the wire** — observing two conflicting signed
  messages at one view. The precompile *verifies* a proof; it does not *detect*.
- **Live signer / vote verification** — per-message, pre-execution, against the
  live key cache (the lagged registry can't answer "now").
- **Genesis / bootstrap set** — seeds both consensus and the registry.

## Build sequencing

1. **`Registry` predeploy + genesis seed + `keyAt` read** — the foundation;
   fork-free, Prague-independent, unit-testable here. Also unblocks **#729's
   governance tally** (read validator weights/keys from EVM).
2. **Wire rotation → registry storage** — extend the #730 flow to record key
   history; add the consistency-frontier accessor.
3. **`Slashing` predeploy (b)** — Prague + BLS only; lands after #740 is
   droplet-finalised and (1)+(2) exist. Verifies via EIP-2537, slashes, emits.
4. **boule read/apply of `Slashed`** — reuse the staking read path.

Steps 1–2 are buildable and testable in CI now (no live EL); step 3 needs a live
Prague reth to exercise the EIP-2537 path end-to-end.

## BLS verification — validated against a live reth

The crypto core of step 3 is **verifying a boule BLS signature in the EVM**.
This is confirmed feasible: against ground-truth vectors from boule's own blst
(generated by `crypto::sig_scheme::tests::gen_eip2537_vectors`), the EIP-2537
**pairing precompile (`0x0f`) returns true** for `e(pubkey, H)·e(-G1gen, sig)`
on a live reth v2.2.0, and rejects a tampered signature. So:

- **Point encoding** (the gotcha) is settled: G1 = `x‖y`, each Fp 16-byte-zero-
  padded to 64; G2 = `x.c0‖x.c1‖y.c0‖y.c1` (c0 = blst affine `.fp[0]`). Don't
  byte-copy blst's compressed/`serialize()` output — extract affine coords.
- **Verify equation**: `PAIRING_CHECK([pubkey_G1, H_G2], [-G1gen_G1, sig_G2]) == 1`.
- **What the precompile still must compute itself** (so it doesn't trust a
  caller-supplied `H`): `H = hash_to_curve(msg)` in Solidity — RFC 9380
  `expand_message_xmd` over the **SHA-256 precompile (`0x02`)** with boule's DST
  `BOULE_HOTSTUFF_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, `hash_to_field`
  (2 Fp2 elements; reduce each 64-byte block mod p via the MODEXP precompile
  `0x05`, exp 1), `2× MAP_FP2_TO_G2` (`0x11`), `G2ADD` (`0x0d`). Cofactor
  clearing is linear, so map-each-then-add equals the RFC's add-then-clear.
- **`msg`** is the canonical pre-image boule signs (see `sig_scheme`); the
  equivocation proof carries two `(view, block_hash)` messages that must differ
  only in `block_hash` at the same `view`.

**Update — the full in-EVM verify is now built and verified** (`contracts/BlsVerify.sol`):
the in-Solidity hash-to-curve (`expand_message_xmd` over SHA-256 → MODEXP-reduce
→ `2× MAP_FP2_TO_G2` → `G2ADD`) produces a point **byte-identical to blst's H**,
and `verify(pubkey, msg, sig, -G1gen)` returns true for a real boule signature
and false for a tampered message — confirmed on a live reth via
`contracts/test/blsverify.mjs` against the blst vectors. So the crypto core of
the slashing precompile is done.

**Update — the predeploy wrapper is now built** (`contracts/Slashing.sol`,
deployed as the genesis predeploy at `0x…b13`). It inherits `BlsVerify`, reads
`Registry.keyAt(validator, view)`, reconstructs the two `preimage::<Vote>`
signing messages from the equivocation proof (`chain_id ‖ u32_be(len(DST)) ‖ DST
‖ varint(view) ‖ block_hash`), checks same-`view`/different-`block_hash`,
verifies both signatures, and on success emits `Slashed`. Validated against a
**live reth** (`contracts/test/slashing.mjs`) with ground-truth equivocation
vectors from boule's blst (`gen_slashing_vectors`): a valid double-sign emits
`Slashed`, while a same-block proof or a signature that doesn't match its block
reverts. It only *verifies + signals* — `chainId` is caller-supplied but a wrong
value can't forge a slash (the pre-image won't verify).

Remaining for #732: **boule's read/apply of `Slashed`** (the #655 `eth_getLogs`
path → `StakeSource` → jail, step 4 below) and the registry **write path** that
records committed rotations plus the `settledFrontier` gate (step 2). The
predeploy trusts `keyAt` as settled until that frontier lands.

## The write path (#732 step 2) — what was built, and why rotations don't decode in-EVM

Step 2 ("populate the registry automatically so it mirrors consensus") splits
into the two writes the registry takes: **genesis** and **rotations**. They have
very different feasibility, so they are handled differently.

### Genesis seed — done, validated on a live reth

The genesis validators' keys are written directly into the registry predeploy's
**genesis storage** (`alloc[Registry].storage`), the EVM analogue of
`BlsKeyHistory::with_genesis`. `registry::genesis_seed_storage` derives the
`(slot -> value)` words for a `mapping(bytes32 => KeyEntry[])` (each genesis
validator a one-element `[(vEff: 0, key)]` history) and
`genesis_seed_storage_json` renders them for an `alloc[…b12].storage` block.

The storage-slot layout (the doc's "fiddliest part") is:

- `history` is the contract's only state variable → declaration slot `0`.
- `history[validator]` array: `arraySlot = keccak256(validator ‖ uint256(0))`
  holds the **length**; elements start at `dataBase = keccak256(arraySlot)`.
- A `KeyEntry { uint64 vEff; bytes key; }` occupies **2 slots** (the `uint64`
  does not pack with the trailing dynamic `bytes`): element `i` is
  `vEff` at `dataBase + 2i`, `key` header at `dataBase + 2i + 1`.
- A 48-byte BLS key exceeds 31 bytes → the `bytes` **long form**: the header slot
  holds `2*len + 1` (= 97), and the bytes live at `keccak256(headerSlot)`, one
  32-byte slot at a time (48 bytes → 2 slots, the second right-padded).

Validated end-to-end against reth v2.2.0 (`contracts/test/registry-seed.mjs`):
a genesis seeded for `(validator = 0xaa*32, key = 0x11*48, vEff = 0)` returns the
exact derived words from `eth_getStorageAt`, and the contract reads its own
seeded storage as a valid history — `historyLength == 1`, `keyAt(v, 0)` and
`keyAt(v, 5)` both return the seeded key. The Rust slot derivation is pinned to
those live-reth ground-truth words in a unit test.

Note: the committed `genesis.template.json` carries **no** validator keys — they
are per-deployment, so the seed is produced by the (future) deployment-specific
genesis builder calling `genesis_seed_storage`, exactly as consensus calls
`BlsKeyHistory::with_genesis` with the deployment's genesis set. The pin test
uses a synthetic vector, not template state.

### Rotations — NOT decoded in Solidity (deliberate). Recommended: boule-side recording.

The original plan (b) was to extend `Rotation.submitRotation` so the predeploy
*also* decodes `(vEff, newBlsKey)` from the carried `rotationCommand` and calls
`Registry.recordKey`. **Investigated and rejected as impractical.** The command
is `ROTATION_TAG ‖ postcard(DualSignedRotation)` — a **postcard** binary
encoding (`boule-consensus/src/validator_rotation.rs::encode_command`), and
postcard is hostile to in-EVM decoding:

- `vEff` (`View(u64)`) is a **LEB128 varint** of *data-dependent length*
  (1–10 bytes). Every field after it sits at a variable offset, so there are no
  constant calldata slices — Solidity would need a hand-rolled varint loop that
  re-bases all downstream offsets.
- `new_bls_pubkey` is `Option<&[u8]>` (`serde_optional_bls_pubkey` serializes the
  48 bytes *as a slice*): an `Option` tag byte (0x00/0x01) **plus a varint length
  prefix**, not a fixed 48-byte field — another varint and another branch.
- `new_pubkey` (the Ed25519 half) precedes the BLS field, and both signatures
  (`sig_old`, `sig_new`, each a length-prefixed 64-byte slice) follow it, so the
  parser must walk the whole structure to reach the BLS key.

Decoding non-self-describing varint-framed postcard in Solidity is expensive,
brittle, and would **couple the contract to postcard's internal wire format** —
a layer the rotation predeploy is explicitly designed to treat as opaque
("consensus validates it; the EVM never interprets it"). It also re-implements,
unverified, parsing that boule already does correctly. So path (A) is not taken.

**Recommended rotation→registry recording (in priority order):**

1. **boule-side recording (recommended).** boule already decodes every committed
   rotation (`DualSignedRotation::decode_command`) to drive its own
   `BlsKeyHistory`. At that same point — where it has the verified
   `(validator, v_eff, new_bls_pubkey)` in hand — it submits a
   `Registry.recordKey(validator, v_eff, key)` transaction (or, cleaner, the EL
   applies it as part of executing the rotation effect). This keeps the *single
   authoritative decoder* (consensus) as the only thing that parses the command,
   makes the registry a strict function of what consensus already accepted, and
   needs **no** Solidity decode. The MVP `recordKey` is unauthenticated, so a
   plain external call suffices; the #732 hardening (verify the dual signature
   in-EVM before recording) can be layered on later via the same `BlsVerify`
   path the slashing precompile uses.

2. **A dedicated `Registry.recordRotation(validator, vEff, key)` entrypoint** the
   rotation flow calls with *already-decoded* fields (decode happens boule-side,
   as in 1). Functionally identical to calling `recordKey`; only worth a separate
   selector if recording should carry rotation-specific authorization distinct
   from the generic `recordKey`. For the MVP, `recordKey` is sufficient.

3. **In-Solidity decode inside `submitRotation`** — rejected, per above.

Either of (1)/(2) preserves the "Mirror, not inversion" and consistency/lag
contract above: the write is driven by the *same* committed submission consensus
consumes, future-dated to `v_eff`, and the slashing precompile only trusts views
at/below `settledFrontier`.

## Open questions

- **Storage layout for a dynamic per-validator history** in Solidity storage
  (mapping of validator → dynamic array) and its genesis pre-population — the
  genesis-storage encoding is the fiddliest part.
- **`settledFrontier` derivation in-EVM** — *resolved (#732).* The registry
  holds an explicit `settledView` checkpoint (slot 3), advanced by the proposer
  each commit via the WRITER-gated `recordSettled(viewNum)` with the
  just-committed view; `Slashing.submitEquivocation` reverts (`"view not
  settled"`) unless `view <= settledView`. It is **exact, not conservative**:
  every rotation is future-dated (`vEff > commitView`, `V_EFF_MIN_DELAY >= 2`),
  so a rotation effective at view `V` was committed — and therefore recorded —
  at a view strictly before `V`; once view `C` commits, every rotation with
  `vEff <= C` is already recorded, making `C` the highest fully-recorded view.
  (The committed-block-height = executed-view 1:1 mapping, #674, is what lets the
  proposer pass the view it just committed.)
- **Slash magnitude / partial slashing** — full burn (today's #658b) vs. a
  fraction; an economic-policy decision orthogonal to the mechanism.
- **Stake reads for #729's governance tally** — the same registry should expose
  weights so the governance predeploy can tally validator-weighted quorum; align
  the read surface so #729's producer and (b) share one registry.
