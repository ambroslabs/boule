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

## Open questions

- **Storage layout for a dynamic per-validator history** in Solidity storage
  (mapping of validator → dynamic array) and its genesis pre-population — the
  genesis-storage encoding is the fiddliest part.
- **`settledFrontier` derivation in-EVM** — cleanest source (registry's own EVM
  block height vs. an explicit checkpoint the rotation flow advances).
- **Slash magnitude / partial slashing** — full burn (today's #658b) vs. a
  fraction; an economic-policy decision orthogonal to the mechanism.
- **Stake reads for #729's governance tally** — the same registry should expose
  weights so the governance predeploy can tally validator-weighted quorum; align
  the read surface so #729's producer and (b) share one registry.
