# Execution-layer transaction integration surface

Design notes for **milestone #4** — *route all transactions through the
execution layer*. This is the reference an execution-layer (EL) backend
implements: for every consensus behaviour that can be expressed as a
transaction, it gives the consensus→EL signal the behaviour consumes, the
EL→consensus effect it emits, what stays consensus-native, and whether a given
**validator-authority model** needs it at all.

Tracking issue: #726. The enabling primitive (the widened `CommitResult`): #727.

## The principle

Anything that is a *transaction* rides the execution layer's pipe — its
mempool, gossip, RPC, nonce/replay, and fee market. Consensus does **not** keep
a parallel transaction layer. Two notions of "transaction" remain (an EL
transfer is not a membership change), but there is **one pipe**: an EVM
precompile/predeploy for reth, message types behind a richer-than-ABCI shim for
Cosmos, a module for Move.

A consequence: an EL that wants to drive a validator-relevant behaviour
*authorises the transaction itself* (e.g. an EVM precompile verifies a
dual-signed key rotation), then reports the resulting **typed effect** to
consensus. Consensus applies the typed effect; it never reads "EVM logs"
directly.

## The seam (bidirectional)

| direction | type | what it carries |
|---|---|---|
| consensus → EL | [`AppContext`] | `proposer`, `last_commit` (the justifying QC's signers + weights), `evidence` (resolved misbehaviour offenders) — read-only, consensus-uninterpreted |
| EL → consensus | [`CommitResult`] | `validator_updates` (ABCI-shaped weight deltas), `effects: Vec<ValidatorEffect>` (the richer categories), `app_data` |

`AppContext` field population differs by call site: at `build_proposal`
`proposer` is the local node and `last_commit` is resolved from the extended
`high_qc` (`evidence` empty); at `commit` `proposer` is the committed block's
and `evidence` is resolved (`last_commit` is empty today — no commit-time
consumer needs it yet).

`CommitResult` effects are **materialised** by minting the carried consensus
system command into the next proposal this node builds as leader (deferred
materialisation — `mint_staged_reconfig` for weight deltas, `mint_staged_effects`
for the richer effects). Minting a *command* — rather than mutating consensus
state at commit — is what keeps recovery sound: the startup integrity check
re-derives validator history from committed block *commands*.

## What stays consensus-native (cannot move to a lagged EL)

These are irreducible: they are per-message and pre-execution, or they are the
bootstrap, so a deferred/lagged execution layer cannot answer them.

- **Live signer / vote verification at ingress** — `verify_signer_at`, run on
  every consensus message before execution.
- **Equivocation *detection* on the wire** — observing two conflicting
  signed messages at the same view. (Note: equivocation *verification* of an
  already-collected proof is **not** native — a precompile can verify it from
  settled historical key state. See "Evidence / slashing" below.)
- **Genesis / bootstrap validator set** — the set consensus starts from.
- **Key-rotation `v_eff` timing and live active-key selection** — which key is
  active at the current view.

Everything else is a candidate to express as an EL transaction.

## Capability catalog

Each row is one [`IntegrationCapability`]. "Consensus-native residue" is the
part that stays in consensus no matter who drives the transaction.

### Membership / governance (weight, add, remove)
- **Consumes:** — (proposer/last_commit only indirectly, for rewards).
- **Emits:** `CommitResult::validator_updates` (ABCI `{node_id, weight}`; `0`
  removes). A full governance reconfig that *adds* a validator needs an endpoint
  (see below), so adds route through the endpoint/governance path (#729), not a
  weight-only update.
- **Consensus-native residue:** apply at a `v_eff` boundary, one-reconfig-at-a-
  time, `MIN_VALIDATOR_FLOOR`, history rebuild on recovery.
- **Authority model:** PoA — **none** (static set). PoS — **required** (weight
  derives from stake).

### Key rotation (signing + operator key)
- **Consumes:** —.
- **Emits:** `ValidatorEffect::KeyRotation(bytes)` — the encoded
  [`DualSignedRotation`] (or operator/cancel variant) the EL already authorised.
- **Consensus-native residue:** `v_eff` timing, live active-key selection,
  signature re-verification at apply, the `RotatableSigner`.
- **Authority model:** optional for all (key management, not economics).
- **Status:** materialiser wired (#727); EL producer is #730.

### Endpoint advertisement
- **Consumes:** —.
- **Emits:** `ValidatorEffect::EndpointUpdate(bytes)`.
- **Consensus-native residue:** endpoint-registry replay guard, dialling.
- **Authority model:** optional; needed to *add* validators (an add carries an
  endpoint).
- **Status:** ⚠️ **gap** — the endpoint-registry mechanism (#546) is not on
  `main`; the materialiser surfaces this effect as unsupported. Tracked by #731.

### Evidence / slashing
- **Consumes:** `AppContext::evidence` (offenders already resolved through the
  key history; the proof is pre-verified by consensus).
- **Emits:** `CommitResult::validator_updates` with `weight 0` (the membership
  *jail*) and/or `Application::slash(node_id)` (the economic stake burn).
- **Consensus-native residue:** equivocation *detection*; live signer verify.
  Evidence *verification* of a collected proof can be a precompile (it needs
  only settled historical key state).
- **Authority model:** PoA — jail-only (membership). PoS — jail **plus** stake
  slash (economic). Both optional in the sense that a chain may choose not to
  penalise.

### Rewards
- **Consumes:** `AppContext::last_commit` (who signed the justifying QC, with
  weights) and `proposer`, at `build_proposal`.
- **Emits:** typically nothing to consensus (reward balances are EL-internal);
  may emit `validator_updates` if rewards change voting weight.
- **Consensus-native residue:** none — pure EL accounting.
- **Authority model:** **PoS-with-rewards only**, and *never forced*. A chain
  without an incentive layer wires nothing here.

### Consensus-parameter updates
- **Consumes:** —.
- **Emits:** `ValidatorEffect::ParamUpdate(bytes)`.
- **Consensus-native residue:** apply the parameter at a boundary.
- **Authority model:** optional.
- **Status:** ⚠️ **gap** — no consensus apply path on `main`; the materialiser
  surfaces this effect as unsupported. Tracked by #542.

## Required vs optional, by authority model

The seam exposes *capabilities*; each backend implements only the subset its
authority model needs. **Consensus must run with zero capabilities wired** —
that is the PoA case.

| capability | PoA / fixed set | PoS (no rewards) | PoS + rewards |
|---|---|---|---|
| Membership | — | required | required |
| Key rotation | optional | optional | optional |
| Endpoint advertisement | optional | for adds | for adds |
| Slashing | jail (optional) | jail + stake | jail + stake |
| Rewards | — | — | required |
| Parameter updates | optional | optional | optional |

The reth EL's *default* (`CommitResult::default()`, no declared capabilities)
behaves exactly as the pre-seam `Result<()>` return: it drives nothing, and
Ethereum keeps the validator set in its own consensus layer.

## Making a missing hook visible

Two mechanisms keep the surface from being silent:

1. **[`IntegrationCapability`]** (`#[non_exhaustive]`) is the in-code catalog —
   one variant per row above. A backend *declares* the subset it drives via
   [`Application::capabilities`] (default: none); the node logs the declared set
   when an application is wired, so an operator can see at a glance what a
   backend does and does not drive.
2. **[`ValidatorEffect`]** (`#[non_exhaustive]`) — when a backend emits an
   effect whose consensus apply path does not exist yet (endpoint, parameter),
   the materialiser logs it as *unsupported and dropped* rather than silently
   ignoring it.

An integrator implementing a new EL reads the `IntegrationCapability` variants
as the checklist of everything they *could* wire, and the catalog above for how
each maps onto the seam.

[`AppContext`]: ../crates/boule-consensus/src/replication/application.rs
[`CommitResult`]: ../crates/boule-consensus/src/replication/application.rs
[`ValidatorEffect`]: ../crates/boule-consensus/src/replication/application.rs
[`IntegrationCapability`]: ../crates/boule-consensus/src/replication/application.rs
[`Application::capabilities`]: ../crates/boule-consensus/src/replication/application.rs
[`DualSignedRotation`]: ../crates/boule-consensus/src/validator_rotation.rs
