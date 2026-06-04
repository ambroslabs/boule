# The transaction-integration surface

The integrator-facing catalog for **milestone #4** — *route all transactions
through the execution layer (no bespoke consensus tx layer)*. For every
consensus behaviour an execution-layer (EL) backend *may* expose as a
transaction, this lists: the seam hook it rides, whether a given
**validator-authority model** needs it, the reth-native form that realises it
(which predeploy, its genesis address, its event), the
[`ValidatorEffect`] it produces, and the boule read/apply path.

Tracking issue: #726. The enabling primitive — the widened [`CommitResult`]:
#727. The in-code companion to this doc is [`IntegrationCapability`]
(`#[non_exhaustive]`): one variant per behaviour, declared by a backend via
[`Application::capabilities`] so the node logs the subset a backend drives.

This doc is the *surface*, not a status board: it describes the seam as it now
exists on `main`. Where a piece is still hardening (an unauthenticated MVP
write, a count-not-weight tally) it says so inline, but the shape is stable.

## 1. The principle

A **transaction** is something submitted to be included in a block and acted
upon. Two notions of "transaction" coexist — an EL token transfer is not a
membership change, and consensus cares about the difference — but milestone #4
collapses them onto **one pipe**: a transaction rides the EL's mempool, gossip,
RPC submission, nonce/replay and fee market. Consensus keeps no parallel
transaction layer.

The EL integration's job is to **expose consensus-relevant behaviours as
transactions** and drive their effects back through the application seam
([`crate::replication::application`]: the [`Application`] trait, [`AppContext`],
[`CommitResult`], [`ValidatorEffect`]). A backend that wants to drive a
validator-relevant behaviour *authorises the transaction itself* — an EVM
precompile verifies a dual-signed key rotation, a governance predeploy tallies a
reconfig to quorum — then reports the resulting **typed effect** to consensus.
Consensus applies the typed effect; it **never reads "EVM logs" directly**. For
reth that pipe is an EVM precompile/predeploy; for a Cosmos adapter, message
types behind a richer-than-ABCI shim; for Move, a module.

The reth realisation of the pattern is uniform: each predeploy is a **dumb
carrier** that emits an event whose dynamic `bytes` is an *already-encoded,
opaque* boule consensus command. boule reads the event from each committed block
(`eth_getLogs`), wraps the bytes in a [`ValidatorEffect`], and re-materialises
the carried command into a real block command — where the existing consensus
path validates it (signatures / `v_eff`) and applies it. Carrying the *command*
(rather than mutating consensus state at commit) is what keeps recovery sound:
the startup integrity check re-derives validator history from committed block
*commands*, so any boundary an effect introduces must first become a real
command in a block.

## 2. The bidirectional seam

| direction | type | what it carries |
|---|---|---|
| consensus → EL | [`AppContext`] | `proposer`, `last_commit` (the justifying QC's signers + weights, [`VoteInfo`]), `evidence` (resolved misbehaviour offenders, [`Evidence`]) — read-only, consensus-uninterpreted |
| EL → consensus | [`CommitResult`] | `validator_updates: Vec<ValidatorUpdate>` (ABCI-shaped weight deltas), `effects: Vec<ValidatorEffect>` (the richer categories), `app_data: Option<Bytes>` |

**consensus → EL — [`AppContext`].** Field population differs by call site. At
[`Application::build_proposal`]: `proposer` is the local building node and
`last_commit` is resolved from the extended `high_qc` (`evidence` empty — the
leader's evidence-embedding decision lands in the block's commands). At
[`Application::commit`]: `proposer` is the committed block's, and `evidence` is
the resolved offenders from the block's evidence commands (`last_commit` is
empty today — no commit-time consumer needs it yet; the reth EL ignores
`AppContext` entirely). [`VoteInfo`] is `{ validator, weight }`; [`Evidence`] is
`{ offender, view }`, with consensus having already verified the proof and
resolved the offender through the key history.

**EL → consensus — [`CommitResult`] (#727).** The widened return value of
[`Application::commit`]. [`Default`] is "nothing to report" (the reth EL's
default behaviour, behaviourally identical to the pre-seam `Result<()>`). Two
effect channels plus an escape hatch:

- `validator_updates: Vec<ValidatorUpdate>` — the ABCI `{ node_id, weight }`
  voting-weight deltas; `weight == 0` removes, `>= 1` adds/changes. The common
  PoS/staking case.
- `effects: Vec<ValidatorEffect>` — the richer categories, each carrying the
  already-encoded consensus **system command** it materialises into (not raw EL
  state). The [`ValidatorEffect`] enum (`#[non_exhaustive]`):
  - `KeyRotation(Bytes)` — a signing-/operator-key rotation the EL already
    authorised, carried as the encoded [`DualSignedRotation`] (or
    `OperatorSignedRotation` / `DualSignedOperatorRotation` / a cancel). The
    embedded signatures are re-verified at apply, so the minting proposer need
    not be the rotating validator.
  - `EndpointUpdate(Bytes)` — a validator endpoint-list update, carried as the
    encoded [`SignedEndpointCommand`]; the signature + monotone `seq` are
    verified at apply via the endpoint registry.
  - `ParamUpdate(Bytes)` — a live consensus-parameter change, carried as the
    encoded [`ConsensusParamUpdate`]; validated against the `v_eff` delay floor
    and scheduled at its view boundary.
  - `Reconfig(Bytes)` — a governance-approved membership reconfiguration,
    carried as the encoded [`ReconfigCommand`] and minted **verbatim** (an add's
    `consent_sig` pre-image is bound to the command's `v_eff`, so consensus must
    not recompute it), under the same one-reconfig-boundary-at-a-time discipline
    as the staking path.
- `app_data: Option<Bytes>` — an opaque `app_data`-style per-commit escape
  hatch; its commitment story is deliberately unsettled, so the integration
  layer ignores it today.

Each effect is **materialised** by minting the carried command into the next
proposal this node builds as leader (deferred materialisation). A backend emits
only the variants its authority model uses; a PoA / genesis-fixed-set backend,
and the reth EL's *default*, emit none.

## 3. The capability catalog

One row per consensus behaviour. "boule read/apply" is the path from the EL
event to a committed consensus command. Addresses are the genesis-predeploy
addresses copied from `crates/boule-reth/src/*.rs` (mirrored in
`crates/boule-reth/contracts/README.md` and pinned to the generated bytecode by
unit tests). Each reth predeploy is a genesis predeploy (the beacon-deposit
pattern): its runtime bytecode is embedded under `alloc` in the build-generated
`genesis.json`, so no deployment tx is needed.

| Behaviour | Req / Opt (by authority model) | reth-native form (predeploy · address · event) | `ValidatorEffect` | boule read/apply |
|---|---|---|---|---|
| **Staking → membership** (#655) | PoA: — · PoS: **required** | `Staking.sol` · `0x…0b0e` · `Deposit` / `Withdraw` | — (drives `validator_updates`) | `staking::parse_stake_logs` → `StakeSource` → `validator_updates` → reconfig (`derive_validator_updates`) |
| **Key rotation** (#730) | optional (all models) | `Rotation.sol` · `0x…0b0f` · `RotationSubmitted(bytes32,bytes)` | `KeyRotation(Bytes)` | `rotation::parse_rotation_logs` → `derive_rotation_effects` → rotation validate/`v_eff` swap |
| **Endpoint advertisement** (#731 / #546) | optional; needed to *add* validators | `Endpoint.sol` · `0x…0b10` · `EndpointSubmitted(bytes32,bytes)` | `EndpointUpdate(Bytes)` | `endpoint::parse_endpoint_logs` → `derive_endpoint_effects` → endpoint registry (sig + monotone `seq`) |
| **Consensus-parameter update** (#542) | optional (all models) | `Param.sol` · `0x…0b11` · `ParamSubmitted(bytes)` (no indexed validator) | `ParamUpdate(Bytes)` | `param::parse_param_logs` → `derive_param_effects` → `ConsensusParamHistory` (`v_eff` floor) |
| **Validator key registry** (#732a) | EVM-internal (read by slashing) | `Registry.sol` · `0x…0b12` · `KeyRecorded(bytes32,uint64,bytes)` | — (in-EVM `keyAt` read; written by `recordKey`) | not read via logs — the slashing precompile `SLOAD`s it; boule *writes* it (`record_rotated_keys`, proposer-only) |
| **Equivocation slashing** (#732b) | PoA: jail-only · PoS: jail + stake burn | `Slashing.sol` · `0x…0b13` · `Slashed(bytes32,uint64,bytes32,bytes32)` | — (drives `validator_updates` / `Application::slash`) | `slashing::parse_slashed_logs` → `StakeSource::slash` → `weight 0` removal merged with jail (#658) |
| **Governance reconfig** (#729) | optional (membership-governance models) | `Governance.sol` · `0x…0b14` · `Approved(bytes32,bytes)` | `Reconfig(Bytes)` | `governance::parse_approved_logs` → `derive_governance_effects` → reconfig validate + `v_eff` boundary |
| **Rewards** (#659) | **PoS-with-rewards only**, never forced | not built | — | reads [`AppContext::last_commit`] at build; reward balances EL-internal — **not yet built** |

Notes on the read paths (all in `crates/boule-reth/src/application.rs`,
[`RethApplication::commit`]):

- The submission predeploys (rotation, endpoint, param, governance) share one
  generic reader, `derive_predeploy_effects` (`eth_getLogs` → parse dynamic
  `bytes` → wrap in a [`ValidatorEffect`]); the opaque command is **not**
  interpreted in reth.
- Staking and slashing are read together in `derive_validator_updates`: the
  `Slashed` event is applied straight to the `StakeSource` (`slash`), not
  carried as an effect — it surfaces as a `weight 0` removal in
  `validator_updates`, which the integration layer merges with the membership
  jail (#658a) through the reconfig path.
- A failed `eth_getLogs` for any category is logged and yields no
  effects/updates for that block; a transient RPC error must never fail the
  commit (consensus commits regardless of the EL).

**reth's declared capabilities** ([`RethApplication::capabilities`]):
`Membership`, `Slashing`, `KeyRotation`, `EndpointAdvertisement`,
`ParameterUpdates` — explicitly **not** `Rewards`.

### Required vs optional, by authority model

The seam exposes *capabilities*; each backend implements only the subset its
authority model needs. **Consensus must run with zero capabilities wired** —
that is the PoA / genesis-fixed-set case (it declares none, and runs with a
static set).

| capability | PoA / fixed set | PoS (no rewards) | PoS + rewards |
|---|---|---|---|
| Membership (staking) | — | required | required |
| Key rotation | optional | optional | optional |
| Endpoint advertisement | optional | for adds | for adds |
| Slashing | jail (optional) | jail + stake | jail + stake |
| Consensus-parameter updates | optional | optional | optional |
| Governance reconfig | optional | optional | optional |
| Rewards | — | — | required |

### In-progress hardening (surface is stable, authorisation is not)

These are MVP gaps in *who may submit*, not in the seam shape:

- **Registry write path** — `Registry.recordKey` is unauthenticated in the MVP
  (boule submits it from the system account, proposer-only and idempotent via a
  monotone `vEff` guard). Contract-side access control gating `recordKey` to the
  system account, and the `settledFrontier` gate on the slashing precompile, are
  the next #732 steps. See `docs/validator-registry-and-slashing.md`.
- **Governance tally** — `Governance.sol` counts *distinct approving addresses*
  (one-validator-one-vote), not stake weight; `quorum` is a count fixed by the
  first approver. Stake-weighting the tally and restricting `approve` to seated
  validators is the #729 follow-up.
- **Parameter authorisation** — `Param.sol` emits whatever is submitted; who may
  change a consensus parameter (a governance multisig, a validator-quorum
  signature) is an open #542 follow-up. The only consensus-side guard today is
  the `v_eff` delay floor.

In every case consensus still validates the carried command at commit, bounding
the exposure of an over-permissive submission.

## 4. What stays irreducibly consensus-native

These cannot move to a deferred/lagged EL — they are per-message and
pre-execution, or they are the bootstrap:

1. **Live signer / vote verification at ingress** (`verify_signer_at`) — run on
   every consensus message before execution. A lagged EL cannot gate vote
   admission; consensus owns a *live* validator-key history for this.
2. **Equivocation *detection* on the wire** — observing two conflicting signed
   votes at one view. Consensus is what sees them.
3. **The genesis / bootstrap validator set** — before the EL produces anything;
   it seeds both consensus and the EVM registry.
4. **Key-rotation `v_eff` timing and live active-key selection** — which key is
   active at the current view. The swap lands at a view consensus controls
   (future-dated so the execution lag is absorbed).

**Boundary correction — evidence *verification* is NOT irreducible.** A
precompile can verify an equivocation proof (the BLS sig checks plus
same-view/different-hash) against *settled* historical key state — which is
exactly what the slashing predeploy (`Slashing.sol`) + registry (`Registry.sol`)
now do: the registry mirrors boule's per-validator BLS key history into EVM
storage, and the precompile `SLOAD`s `keyAt(validator, view)` for a past view
that is lag-free. The hard residue is the *live* path (1), not the historical
one. See `docs/validator-registry-and-slashing.md` for the consistency/lag
contract (the `settledFrontier` boundary) and the "mirror, not inversion"
argument that keeps consensus authoritative.

## 5. How to add a new capability

The minimal recipe for an integrator exposing a new consensus behaviour as an EL
transaction. Take **endpoint advertisement (#731)** as the canonical end-to-end
example (a dumb carrier; rotation is structurally identical):

1. **A predeploy that emits an event carrying an opaque consensus command.**
   `Endpoint.sol` exposes `submitEndpoint(bytes32 validator, bytes
   endpointCommand)` and emits `EndpointSubmitted(validator, endpointCommand)`.
   `endpointCommand` is the *already-signed* boule command
   (`SignedEndpointCommand::encode_command()`); the EVM never interprets it.
2. **Genesis-seed its address.** It is a genesis predeploy at
   `0x…0b10`; `build.rs` compiles the `.sol` (pinned solc 0.8.24) and embeds the
   runtime bytecode under `alloc` in the generated `genesis.json`.
3. **A `src/<name>.rs` with the identifier constants pinned to the bytecode.**
   `src/endpoint.rs` declares `ENDPOINT_ADDRESS = "0x…0b10"`, `ENDPOINT_TOPIC`,
   `SUBMIT_SELECTOR = [0x18, 0xd8, 0x84, 0x38]`, plus `logs_filter(block_hash)`
   and `parse_endpoint_logs`. Unit tests pin the address/topic/selector to the
   generated bytecode (mirrored in `contracts/README.md`).
4. **A `derive_<name>_effects` read in [`RethApplication::commit`].**
   `derive_endpoint_effects` calls the generic `derive_predeploy_effects`
   (`eth_getLogs` for this block → `parse_endpoint_logs` → wrap each in
   `ValidatorEffect::EndpointUpdate`) and appends the result to the
   `CommitResult::effects`.
5. **The consensus-side apply.** The integration layer materialises the effect
   by minting the carried command into the next proposal; the existing
   `EndpointRegistry` path verifies the signature + monotone `seq` and applies
   it. Add the matching [`IntegrationCapability`] variant and declare it in
   [`Application::capabilities`] so the node logs that the backend drives it.

That is the whole loop: a dumb event carrier on the EL, a constants-only Rust
module, one `derive_*` read appended in `commit`, and an existing
consensus-native validate/apply path on the far side. The command stays opaque
to the EL end-to-end; consensus remains the single authoritative decoder.

[`crate::replication::application`]: ../crates/boule-consensus/src/replication/application.rs
[`Application`]: ../crates/boule-consensus/src/replication/application.rs
[`Application::build_proposal`]: ../crates/boule-consensus/src/replication/application.rs
[`Application::commit`]: ../crates/boule-consensus/src/replication/application.rs
[`Application::capabilities`]: ../crates/boule-consensus/src/replication/application.rs
[`AppContext`]: ../crates/boule-consensus/src/replication/application.rs
[`AppContext::last_commit`]: ../crates/boule-consensus/src/replication/application.rs
[`CommitResult`]: ../crates/boule-consensus/src/replication/application.rs
[`ValidatorEffect`]: ../crates/boule-consensus/src/replication/application.rs
[`ValidatorUpdate`]: ../crates/boule-consensus/src/replication/application.rs
[`VoteInfo`]: ../crates/boule-consensus/src/replication/application.rs
[`Evidence`]: ../crates/boule-consensus/src/replication/application.rs
[`IntegrationCapability`]: ../crates/boule-consensus/src/replication/application.rs
[`DualSignedRotation`]: ../crates/boule-consensus/src/validator_rotation.rs
[`SignedEndpointCommand`]: ../crates/boule-consensus/src/endpoint_registry.rs
[`ConsensusParamUpdate`]: ../crates/boule-consensus/src/consensus_params.rs
[`ReconfigCommand`]: ../crates/boule-consensus/src/reconfig.rs
[`RethApplication::commit`]: ../crates/boule-reth/src/application.rs
[`RethApplication::capabilities`]: ../crates/boule-reth/src/application.rs
