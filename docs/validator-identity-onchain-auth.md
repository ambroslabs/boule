# On-chain validator-identity authentication (#763, #764)

Design notes for the two milestone-#4 production-hardening security issues that
share one root: **there is no way today for an EVM predeploy to know that a
caller controls validator X.** Both the registry write-path (#763) and the
governance/param approval-path (#764) currently authenticate by *naming* a
validator id, never by *proving control of it*.

Tracking: #769 (the production-hardening umbrella). Relates #763, #764, #726,
#732, #729, #746. Prereqs already landed: the `BlsVerify` predeploy (in-EVM
EIP-2537 BLS verify, #748, proven against boule's `blst`), the `Registry`
weight/key surface (#732a/#759), the system-account submission plumbing (#756).

## The two gaps, stated precisely

**#763 — the writer key is public.** `Registry.recordKey` / `recordWeight` /
`recordSettled` gate on `msg.sender == WRITER`, where `WRITER` is the system
account whose secp256k1 key is **committed in the clear**
([`SYSTEM_ACCOUNT_PRIVATE_KEY`](../crates/boule-reth/src/system_account.rs)).
The `WRITER` gate is therefore bypassable by anyone: an attacker can sign as the
system account, `recordKey` a bogus BLS key for an honest validator (then forge
an "equivocation" and slash them), `recordWeight` arbitrary weights (skewing
every weighted quorum), or `recordSettled` the slashing frontier.

**#764 — approvals are unauthenticated.**
[`Governance.approve(bytes32 proposalId, bytes reconfigCommand, bytes32
validator)`](../crates/boule-reth/contracts/Governance.sol) and
[`Param.approve(...)`](../crates/boule-reth/contracts/Param.sol) gate only on
`Registry.weightOf(validator) > 0` and dedup on the **public** `validator` id.
There is no check that `msg.sender` controls `validator`. Since validator ids
are public, one actor can call `approve` once per real validator id, accrue a
⅔ supermajority, and emit a forged `Approved` / `ParamSubmitted` that consensus
then re-materialises and applies. Consensus re-validates the command's
*well-formedness*, not that the validators actually approved — so removes,
weight-driven decisions, and convergence-critical param updates are exposed.

Both reduce to the same missing primitive: **a predeploy-checkable proof that
an action is authorized by the holder of validator X's consensus key.**

## The identity facts that constrain the design

- A validator's stable on-chain id is its **Ed25519 `NodeId`** (`[u8; 32]`,
  `crates/boule-core/src/identity/mod.rs`), used **verbatim** as the
  `Registry`/`Governance`/`Param` `bytes32` key. This is the network/TLS
  identity — *not* a secp256k1/EVM key.
- Every BLS-chain validator **also** holds a **BLS12-381 consensus key** (the
  QC-signing key). Its history is the authoritative
  [`BlsKeyHistory`](../crates/boule-consensus/src/bls_key_history.rs), and the
  `Registry` already **mirrors** it: `Registry.keyAt(validator, view)` returns
  the EIP-2537-form (128-byte G1) BLS pubkey active at a view.
- boule signs BLS with the `min-pk` IETF suite under the DST
  `BOULE_HOTSTUFF_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, and the
  [`BlsVerify`](../crates/boule-reth/contracts/BlsVerify.sol) predeploy already
  verifies exactly that suite in-EVM (`hashToG2` + the EIP-2537 pairing check),
  proven against `blst`.
- Validators do **not** hold a secp256k1/EVM key today. The
  `operator_pubkey` / `consent_sig` on a reconfig add
  (`crates/boule-consensus/src/reconfig.rs`) is **Ed25519** (`NodeId`-typed),
  not an EVM key. So option 2 (below) has nothing to bind to at genesis.
- The proposer write-path is **proposer-gated and single-submitter**: only the
  committed block's proposer (`ctx.proposer == self.self_id`) submits
  `recordKey` / `recordWeight` / `recordSettled`, and `recordSettled` runs on
  **every commit** (`RethApplication::commit`,
  `crates/boule-reth/src/application.rs`). All replicas already hold the same
  authoritative data; the write is a deterministic mirror, not a vote.

## The options

### Option 1 — In-EVM BLS verification (reuse `BlsVerify`)

The actor signs the action with its **consensus BLS key**; the predeploy fetches
the validator's current key via `Registry.keyAt` and verifies the signature with
`BlsVerify._verify` over a domain-separated, replay-bound pre-image.

- **Pro:** no new key custody, no registration/rotation story, no bootstrap
  problem — it ties authorization to the *actual consensus key* the registry
  already holds and the validator already controls. One mechanism, reusing #748
  verbatim, serves both issues. Key rotation is already handled by the registry.
- **Con — gas.** In-EVM BLS verify is heavy: one `hashToG2` (≈8 SHA-256 + 2
  MODEXP + 2 `MAP_FP2_TO_G2` + 1 `G2ADD`) plus one EIP-2537 `PAIRING_CHECK` over
  two pairs. Order-of-magnitude **hundreds of thousands of gas per
  verification** (the pairing precompile alone is the dominant EIP-2537 cost,
  and `hashToG2` adds the MODEXP/map overhead). That is per *write* and per
  *approval*.
- **Con — replay.** A bare BLS signature is replayable across proposals, views,
  chains, and contracts unless the signed pre-image is fully bound (domain tag,
  chain id, contract address, action selector, action arguments, and a
  per-validator nonce or the proposal id).

### Option 2 — EVM-address ↔ validator binding

Validators register a secp256k1/EVM key in the `Registry`, then authorize by
signing the tx as `msg.sender` (cheap secp256k1 `ecrecover`, ~3k gas).

- **Pro:** cheap per action; idiomatic EVM auth.
- **Con — bootstrap.** Validators hold **no EVM key today**. Registration needs
  its *own* authentication (how do you prove the EVM key you're registering
  belongs to validator X?), which lands you right back at "verify a BLS
  signature over the binding" — i.e. option 1 *plus* a new key, a new rotation
  story, and a new compromise surface. It moves the trust problem, it doesn't
  remove it. Genesis would have to seed a per-validator EVM key with no
  established provenance.

### Option 3 — Per-validator authorized writers / threshold key (writer-only)

A custody scheme specific to the #763 system-writer: a per-deployment threshold
or HSM-held key, or an EL-applied system call (beacon-root-contract style) that
needs no externally held key.

- **Pro (EL-applied variant):** removes the externally held key entirely; the
  EL applies the registry mutation as a system call at block construction, so
  there is no signer to compromise and no gas/funding problem.
- **Con:** solves only #763, not #764 (approvals are genuine per-validator votes,
  not a single deterministic system mutation — there is no single "system" actor
  to apply them). The EL-applied variant is the **heaviest** change (it touches
  reth's block-construction path and the engine boundary), and a threshold/HSM
  variant still leaves the trust rooted in operational key management rather than
  the consensus key.

## Recommendation — split by the shape of the action, not the issue

The two issues do **not** want the same mechanism, because the two actions have
fundamentally different trust shapes:

- A **registry write** is a **deterministic mirror** of state every replica
  already agreed on in consensus. It is not a vote; it has exactly one correct
  value per `(validator, view)`. The right model is "the EL applies it," not
  "someone signs it."
- An **approval** is a **genuine per-validator decision**. There is real
  information in *who* approved that exists nowhere else on chain. The right
  model is "the validator proves it approved."

So:

### #763 → Option 3, EL-applied system writes (no externally held key)

Make the registry mutations a **system call applied by the execution layer at
block construction**, gated on `msg.sender == SYSTEM` where `SYSTEM` is the
EIP-4788-style zero-provenance system address that **only the EL itself can
originate from** (no private key exists for it; it cannot be spoofed by a normal
transaction). The proposer no longer holds or funds a writer key.

Concretely:

- `Registry.recordKey` / `recordWeight` / `recordSettled` change their gate from
  `msg.sender == WRITER` (a fundable EOA) to `msg.sender == SYSTEM` (the
  EL-only system caller). The function bodies are unchanged.
- The proposer's `RethApplication::commit` path stops building **signed** system
  txs (`build_system_call`) and instead instructs the EL to apply the same
  calldata as **system calls** during block construction, exactly as the
  beacon-root contract is applied today. The calldata builders
  (`record_key_calldata` / `record_weight_calldata` / `record_settled_calldata`
  in `crates/boule-reth/src/registry.rs`) are reused verbatim.
- **No replay/domain concern:** the mutations are deterministic and idempotent
  (`recordKey` requires strictly increasing `vEff`; `recordSettled` clamps
  monotonically), and they are applied by the EL, not gossiped, so there is
  nothing to replay.
- **Determinism across replicas:** every replica's EL must apply the *same*
  system calls for a given committed block. Because the inputs (the block's
  rotations, seated-weight deltas, and committed view) are already deterministic
  consensus outputs, this holds. The "proposer-only submitter" gating
  (`ctx.proposer == self_id`) is **removed** — every replica's EL applies the
  same mutation locally, which also closes the proposer-rotation / shared-nonce
  race that #766 flags and removes the single-submitter liveness dependency.
- **Operational sustainability (the #763 funding tail):** solved outright — there
  is no EOA, so no gas is charged for the writes and no genesis funding depletes.
  Remove `SYSTEM_ACCOUNT_PRIVATE_KEY`, the genesis funding alloc, and the MVP
  caveat.

Why not give the writer Option 1 (BLS-sign each write)? It would re-introduce a
signer (which validator signs the mirror? the proposer as itself? a quorum?),
re-introduce gas/funding, and pay a heavy pairing **on every commit**
(`recordSettled` runs every block) — all to authenticate data that is already a
deterministic function of agreed state. The EL-applied model is strictly
simpler and removes the key rather than hardening it.

### #764 → Option 1, in-EVM BLS approval signatures

An approval is a real vote, so authenticate it against the key the validator
actually controls. Change `approve` to take the validator's **BLS signature over
the approval** and verify it with `BlsVerify` against `Registry.keyAt`.

```
approve(
    bytes32 proposalId,
    bytes   command,        // reconfigCommand / paramCommand
    bytes32 validator,      // the NodeId being voted as
    bytes   blsSig          // EIP-2537 G2 sig over the auth pre-image
)
```

with the auth check (in both `Governance` and `Param`, factored into a shared
helper):

```
// 1. seated-validator gate (unchanged)
uint64 w = Registry.weightOf(validator); require(w > 0);

// 2. NEW: prove control of `validator`'s consensus key
bytes memory pk = Registry.keyAt(validator, settledView());   // 128-byte G1
bytes32 digest = keccak256(abi.encode(
    AUTH_DOMAIN,          // e.g. keccak256("BOULE_GOV_APPROVE_V1") / "BOULE_PARAM_APPROVE_V1"
    block.chainid,        // cross-chain replay
    address(this),        // cross-contract replay (Gov vs Param)
    proposalId,           // binds to the exact command (proposalId = hash(command))
    validator             // binds to the voter
));
require(BlsVerify._verify(pk, abi.encodePacked(digest), blsSig, NEG_G1_GEN));

// 3. existing tally (dedup by validator, accumulate weight, emit on ⅔)
```

- **Replay / domain separation** is fully closed by the pre-image: `AUTH_DOMAIN`
  separates governance from param and from any future signer use of the BLS key;
  `block.chainid` blocks cross-chain replay; `address(this)` blocks cross-contract
  replay; `proposalId` (already `= hash(command)`) binds the vote to one exact
  command and to the validator. No separate per-validator nonce is needed: the
  contract already dedups by `(proposalId, validator)`, so a replayed identical
  signature for the same proposal is a no-op, and a different command is a
  different `proposalId`.
- **Which key:** verify against `keyAt(validator, settledView())`, i.e. the key
  the registry is *settled* on, so verification never races an unrecorded
  rotation. (A rotating validator signs its approval with the key the registry
  currently holds; this is the same settled-frontier discipline the slashing
  predeploy already uses.)
- **`msg.sender` is now irrelevant** for governance/param — any account can relay
  a validator's signed approval, which is desirable (a watchtower/relayer can
  submit, the validator needn't hold gas or an EVM key).
- **boule also re-verifies (defense in depth):** per #764's "and/or" acceptance,
  `derive_governance_effects` / `derive_param_effects` should re-check the quorum
  from the authenticated approvals rather than blindly trusting the emitted
  event. The in-EVM check makes the event trustworthy; the consensus-side
  re-check means a buggy/forked EL cannot drive a reconfig either.

## Can #763 and #764 share one mechanism?

**No — and they shouldn't.** They share the *root* (no on-chain validator
identity) but not the *fix*, because the actions differ in kind: the registry
write is a deterministic system mirror (best removed from any signer entirely),
the approval is a real per-validator vote (best bound to the consensus key).
Forcing one mechanism onto both is worse on both ends: making the writer
BLS-sign re-adds a signer and pays a pairing every commit; making approvals
EL-applied is incoherent (there is no single system actor that "approves"). The
common asset they reuse is the **consensus BLS key as the root of validator
identity** — option 1 uses it directly for #764, and option 3 sidesteps the need
for any key for #763.

> **If only one mechanism is acceptable for organizational reasons**, choose
> **Option 1 (in-EVM BLS) for both**: writes are BLS-signed by the **proposer as
> itself** (its own seated validator id), over a write-specific domain
> (`BOULE_REGISTRY_WRITE_V1`) binding chain id, contract, selector, and
> arguments, gated on `Registry.weightOf(proposer) > 0`. This keeps custody on
> the consensus key (closing #763's "public key" hole) at the cost of a pairing
> per commit and the proposer paying gas — strictly worse than the EL-applied
> path, but a single uniform mechanism. The split above is the recommendation.

## Bootstrap / genesis story

The recommendation needs **no new key material at genesis** — that is its main
strength.

- **#763:** the `SYSTEM` system-caller address is a fixed, code-only address with
  no private key (EIP-4788 style); nothing to seed, nothing to fund. The genesis
  validators' BLS keys are already seeded into `Registry` storage (the existing
  `alloc[Registry].storage` genesis seed, `validator_history_storage`), so the EL
  system writes append to an already-correct history.
- **#764:** verification reads `Registry.keyAt`, whose **genesis seed already
  establishes the first identities** — the genesis validators' BLS keys are in
  registry storage from block 0. So the very first governance/param approval can
  be authenticated against a genesis-seeded key with no chicken-and-egg. A
  later-added validator's key is recorded by the #763 EL write-path before it can
  be voted as (the registry is updated at the reconfig that seats it), so its
  approvals authenticate against its recorded key too.

This avoids the bootstrap trap that sinks option 2: there is **no moment** where
an identity must be established by an as-yet-unestablished key, because the
consensus BLS key — already authoritative, already genesis-seeded, already
mirrored — *is* the identity.

## Migration off the MVP committed key

1. Land `BlsVerify`-based `approve` on `Governance` + `Param` (#764) behind the
   existing predeploy-bytecode genesis pin. Add the consensus-side quorum
   re-check. Tests: a non-controlling caller's `blsSig` fails `BlsVerify`; a
   forged-supermajority `Approved`/`ParamSubmitted` (no valid signatures) is
   rejected both in-EVM and by the consensus re-check.
2. Land the EL-applied system-write path (#763): switch the `Registry` gate from
   `WRITER` to `SYSTEM`, move `commit`'s write submission from signed txs to EL
   system calls, drop the proposer-only gating. Tests: a normal tx to
   `recordKey`/`recordWeight`/`recordSettled` reverts (`msg.sender != SYSTEM`);
   the EL system call succeeds and every replica's registry converges.
3. **Delete** `SYSTEM_ACCOUNT_PRIVATE_KEY`, `signer()`, `build_system_call`, the
   genesis funding alloc for the system address, and the MVP caveat in
   `system_account.rs` (the module collapses to the `SYSTEM`-address constant and
   the calldata path, or is removed entirely if the EL path owns calldata
   assembly).

## Top risks / costs of the recommendation

1. **EL-applied writes are a reth-integration change, not a contract change**
   (#763). Applying system calls at block construction touches reth's
   block-builder / engine boundary (the EIP-4788-injection seam), which is more
   invasive than the current "proposer submits a signed tx" plumbing and must be
   exercised in the multi-node e2e (#766). If that seam is too costly short-term,
   the fallback is Option 1 for the writer too (proposer-signs, accepting the
   per-commit pairing and gas) — uniform but heavier.
2. **Per-approval BLS gas** (#764). Each `approve` that includes a verification
   pays a `hashToG2` + EIP-2537 pairing — on the order of hundreds of thousands
   of gas, paid by N validators per proposal. This is bounded (reconfigs/param
   updates are infrequent, and the contract dedups so each validator verifies at
   most once per proposal) and acceptable for governance-frequency actions, but
   it must be budgeted against the block gas limit so a proposal with many
   approvers in one block cannot exceed it.
3. **Settled-key timing for approvals.** Verifying against
   `keyAt(validator, settledView())` means a validator that has *just* rotated
   must sign its approval with the key the registry is settled on, not its brand
   new key, until the rotation settles. This is the same discipline the slashing
   predeploy already follows, but it is a sharp edge that must be documented for
   operators and covered by a rotation-during-approval test.
