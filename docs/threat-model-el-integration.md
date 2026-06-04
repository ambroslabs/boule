# Threat model — execution-layer transaction integration (milestone #4)

Adversarial review of the boule → reth write-path / slashing / weighted-quorum
surface that shipped under milestone #4 (#726). This is a **paper review**: it
enumerates assets, attackers, the attack surface, and a per-risk
severity/status/mitigation table, and tries hard to break the system on paper.
It is the deliverable for #768 and feeds the production-hardening umbrella #769.

All citations are to `crates/boule-reth` (the reth backend) and
`crates/boule-consensus` (the safety core) at the time of writing. No production
code is changed here.

> **Scope note.** Several risks are already filed (#763 writer-key custody, #764
> approval auth, #765 genesis weights, #766 multi-node e2e, #767 settled-frontier
> lag). Where a risk maps to one of those, it is marked. Risks **not** covered by
> #763–#767 are marked **NEW** with a suggested issue title/priority/size.

---

## 1. Assets

| # | Asset | Why it matters |
|---|-------|----------------|
| A1 | **Validator BLS key history** in `Registry` (`keyAt(validator, view)`) | The slashing precompile verifies equivocation proofs against it. A wrong/forged key → slash an honest validator, or shield a guilty one. |
| A2 | **Seated weight surface** (`weightOf`, `totalWeight`) | The quorum denominator for #729 governance and #746 param tallies. Skew it → forge or block supermajorities. |
| A3 | **Settled frontier** (`settledView`) | The slashing safety gate. Advance it past real key coverage → slash on a stale key. |
| A4 | **Membership** (the live validator set) | Forged `Approved` reconfig → eject honest validators / seat attacker-controlled ones. |
| A5 | **Consensus params** (`min_block_interval`, future convergence-critical params) | Forged `ParamSubmitted` → degrade liveness/safety. |
| A6 | **The system account** (`0x2Ae0…526`) — signing key + gas balance | The single writer for A1/A2/A3. Its key is custody; its balance is liveness. |
| A7 | **CL-native stake ledger** (`StakeSource`) | The authoritative economic ledger slashing/staking drive; corruption desyncs membership from EL state. |

---

## 2. Attackers

- **EXT — external EVM-tx sender.** Anyone who can land a transaction in reth's
  pool. Holds the *committed, public* system key (it is in the repo). No
  validator status required.
- **MAL — malicious seated validator.** Holds ≤ f weight, can propose blocks
  when it is leader, can author EVM txs, knows every public validator id.
- **SYS — the system account itself / whoever controls its key.** Today this is
  *everyone* (EXT), because the key is public.
- **PART — partitioned / lagging node.** Honest but behind: its reth EL is
  `SYNCING`, or it restarts, or it self-syncs past a gap.

The single structural root of the worst risks is **there is no on-chain binding
between an EVM address and a consensus validator identity** (#763 + #764 share
this root). Two consequences cascade from it: the writer gate is bypassable
(anyone is `WRITER`-equivalent) and approvals are forgeable (anyone can vote as
any validator).

---

## 3. Attack surface (entry points)

1. `Registry.recordKey / recordWeight / recordSettled` — gated only on
   `msg.sender == WRITER`, a **public** address (`Registry.sol:69`,
   `system_account.rs:35`).
2. `Governance.approve(bytes32,bytes,bytes32)` / `Param.approve(...)` — gated only
   on `weightOf(validator) > 0`, no `msg.sender`↔validator binding
   (`Governance.sol:89`, `Param.sol:98`).
3. `Slashing.submitEquivocation(...)` — permissionless; safety rests on the
   registry key + settled-frontier gate, not on the caller (`Slashing.sol:92`).
4. The boule read paths (`parse_*_logs`, `predeploy_log::parse_command_logs`,
   `slashing::parse_slashed_logs`) — turn EVM logs into consensus effects.
5. The proposer write path in `RethApplication::commit` (`application.rs:772`):
   `record_rotated_keys` / `record_validator_weights` / `record_settled_view`,
   all proposer-gated on `ctx.proposer == self_id`.

---

## 4. Risk register

Severity = impact × exploitability **on a real deployment** (not the dev MVP,
where every key is public by construction).

### R1 — System-account key is public → forge the entire registry. CRITICAL

`SYSTEM_ACCOUNT_PRIVATE_KEY` (`system_account.rs:35`) is a committed, well-known
dev key, and `Registry`'s `recordKey`/`recordWeight`/`recordSettled` gate only on
`msg.sender == WRITER == that address` (`Registry.sol:69,92,129,156`). Because the
key is public, EXT *is* the WRITER. Concrete exploits:

- **Forge a key → slash an honest validator.** EXT calls `recordKey(victim,
  vEff, attackerKey)` with `vEff` just past the frontier, then crafts two
  "votes" signed by `attackerKey` and calls `submitEquivocation`. `Slashing`
  reads the forged key from the registry, both sigs verify, `Slashed(victim)` is
  emitted, and `commit` → `derive_validator_updates` → `StakeSource::slash` burns
  the honest validator's stake (`application.rs:154-188`). Note `recordKey` is
  append-only with strictly increasing `vEff` (`Registry.sol:94`), so EXT cannot
  *overwrite* the genesis key — but it can *append* a future-dated forged key and
  then equivocate at a view `>= vEff`, which is enough.
- **Forge weight → skew every quorum.** `recordWeight(attackerId, huge)` inflates
  `totalWeight` or seats a phantom voter; `recordWeight(victim, 0)` removes a
  victim's quorum share. Both #729 and #746 read this surface directly.
- **Forge `recordSettled(C)`** to advance the frontier past real key coverage —
  see R3.

**Status:** open, **#763** (real custody for the writer key). The access control
is structurally present and correct *given* a private key; the whole risk is
custody. Mitigation options in #763: per-validator writer authorization (needs
the #764 address↔validator binding), threshold/derived key, or an EL-applied
system call with no externally held key.

### R2 — Forged-quorum approval (no msg.sender↔validator binding). CRITICAL

`Governance.approve` / `Param.approve` accumulate `weightOf(validator)` and dedup
on the *public* `validator` id, with **no check that `msg.sender` controls
`validator`** (`Governance.sol:89-109`, `Param.sol:98-114`). Validator ids are
public, so a single actor can call `approve` once per real validator id, accrue
`weight*3 > totalWeight*2`, and emit a forged `Approved` / `ParamSubmitted`.

boule then **trusts the event**: `derive_governance_effects` /
`derive_param_effects` (`application.rs:426-457`) wrap the carried command into a
`ValidatorEffect` with no re-tally. Consensus re-materialises it and calls
`ReconfigCommand::validate_against_with_delay_and_scheme`
(`reconfig.rs:360`), which checks **well-formedness only**: `v_eff` delay floor,
no dup/cross-list ids, removes/changes target members, adds don't, weights ≥ 1,
floor size, and — for *adds with an operator key* — the #548 `consent_sig`
(`reconfig.rs:531-551`). It does **not** verify that a validator quorum approved.

What #548 `consent_sig` does and does **not** protect:
- It binds the **inbound** validator's consent to "seat me at these exact terms
  (`addr/weight/v_eff/operator_pubkey`)" (`reconfig_consent.rs`). It protects an
  **add** from seating someone who didn't agree to join.
- It does **nothing** for **removes**, **weight changes**, **keyless adds**
  (`reconfig.rs:548-551` explicitly: "Keyless adds remain unauthenticated"), or
  **param updates**. None of those carry any per-validator authentication, so a
  forged `Approved`/`ParamSubmitted` for a remove / reweight / param change is
  accepted on the event's word alone.

Blast radius is small *today* only because `min_block_interval` is the one wired
param and a forged remove still has to clear `MIN_VALIDATOR_FLOOR`. It becomes
exploitable the moment a convergence-critical param or a remove rides it.

**Status:** open, **#764**. Fix: bind approvals to a key the validator controls
(EVM-address↔validator map authenticated via `msg.sender`, or an in-EVM signature
over the proposal), and/or have consensus re-verify the quorum from authenticated
approvals instead of trusting the producer event.

### R3 — settledFrontier exactness assumes EL-lag ≤ v_eff delay (unenforced). HIGH

`Slashing.submitEquivocation` gates on `view <= settledView` (`Slashing.sol:109`),
and `record_settled_view` advances `settledView` to the just-committed view, run
**after** this block's `recordKey`s (`application.rs:858-862`). The exactness
argument (`Registry.sol:52-58`, `application.rs:372-388`): rotations are
future-dated (`v_eff >= commitView + MIN_V_EFF_DELAY`), so by the time view `C`
commits, every rotation with `vEff <= C` is recorded.

This holds **only if the EL execution lag** — the gap between a rotation
*committing* and its `recordKey` tx *executing* in EVM state — is ≤ the `v_eff`
delay. The `recordKey` is `submit_system_call`'d into reth's pool at commit
(`application.rs:297-318`); it lands some blocks later. There is **no asserted
invariant** in the code tying the #674 EL lag to `MIN_V_EFF_DELAY`. If lag can
exceed the delay, `keyAt(victim, C)` can still be the *pre-rotation* key when
`recordSettled(C)` is written → slashing verifies against the wrong key
(false-negative shields a guilty validator; combined with R1, a false-positive).

Worse, `record_settled_view` runs on the **proposer** unconditionally and clamps
monotonically, but the proposer's own `recordKey`/`recordSettled` are *both* in
the same block's pool and execute with the same lag — so even on the honest path
the frontier can momentarily outrun key coverage if the writes land in different
EVM blocks or out of order (shared-nonce ordering, R8). The "ordered last" claim
holds at *submission* time, not at *execution* time.

**Status:** open, **#767**. Fix: prove and **assert** `EL_lag <= v_eff_delay`, or
make the frontier conservative (`settledView = committedView - lag_margin`, or
only advance once the relevant `recordKey` is observed executed). Prefer
false-negatives (watcher resubmits) over slashing on a stale key.

### R4 — Gas / DoS on the system account: runs dry → registry silently stops. HIGH

The system account pays gas for a `recordSettled` **every commit**
(`application.rs:861`, `record_settled_view`) plus a `recordKey`/`recordWeight`
per rotation/weight change. Funding is **genesis-only and MVP** (`system_account.rs:13-22`,
the `system_account_funded_in_genesis_at_address` test only asserts *non-zero*).
On a chain with a real base fee the balance **depletes monotonically**. When it
runs dry:

- `submit_system_call` fails; `record_*` logs a warning and continues
  (`application.rs:310-317,361-368,401-407`) — **never fails the commit**. So the
  chain keeps committing while the registry **silently stops updating**:
  `settledView` freezes (slashing can no longer accept new-view proofs — fail
  *closed*, safe but a liveness loss for slashing), and `recordKey`/`recordWeight`
  stop (key history and weight surface go **stale** — quorum denominators drift,
  *not* fail-closed). This is a slow-burn correctness failure with no alarm.
- **Amplifying DoS (NEW, see R10):** because EXT holds the system key (R1), an
  attacker can *also* spend the system account's balance and bump its nonce
  (front-running the proposer's nonce), accelerating depletion and causing nonce
  conflicts (R8). So R1 makes R4 actively exploitable, not just an operational
  drift.

`SYSTEM_TX_GAS_LIMIT = 500_000` with `max_fee = 2 gwei` (`system_account.rs:46-53`)
is tuned for `--dev`; on a real base-fee chain the `max_fee` may be *too low* and
txs get stuck pending (a different failure mode: writes never land, same stale
outcome).

**Status:** open. #763 mentions refunding/fee-exemption as a coupled-or-split
sub-item but does not own it as a tracked deliverable. **NEW — split out** (see
R10).

### R5 — Event spoofing / log-parsing. LOW (well handled), with one caveat

The `eth_getLogs` filters are address- **and** topic-scoped (`*::logs_filter`,
e.g. `governance.rs:67`, `slashing.rs:68`, `rotation.rs:42`), so reth only
returns logs *emitted by the correct predeploy*. An EVM contract cannot emit a log
*attributed to another address*, so address-spoofing a predeploy event is not
possible. `parse_command_logs` (`predeploy_log.rs:24`) additionally re-checks
`topics[0]`, validates the ABI `bytes` framing (offset must be `0x20`, length must
fit in 8 bytes and not run past the data — `decode_abi_bytes`/`word_to_usize`,
`predeploy_log.rs:53-82`), and skips anything malformed. `parse_slashed_logs`
(`slashing.rs:86`) requires ≥ 2 topics and a well-formed 32-byte validator word.
Consensus re-validates every command (tag + signatures) before acting, so a junk
log is inert. **This layer is robust.**

Caveat (defense-in-depth, not a live break): the read paths trust *that the
predeploy emitted the event*, but **the predeploys themselves are
under-authenticated** (R1/R2) — i.e. the spoofing risk lives in the *contract's*
admission logic, not the log parser. The parser is doing its job; the events it
faithfully parses can still be adversarial because of R1/R2.

**Status:** parsing layer mitigated. No new issue.

### R6 — Reorg / restart correctness of the proposer write path. MEDIUM

The write path leans on idempotency:
- `recordKey`'s strictly-increasing `vEff` (`Registry.sol:94`) makes a re-proposed
  or post-restart duplicate revert harmlessly (`application.rs:256-259`).
- `recordWeight` **overwrites** and adjusts `totalWeight` by `new-old`
  (`Registry.sol:128-136`); a replay writes the same value (no-op delta).
- `recordSettled` clamps monotonically (`Registry.sol:155-163`).

But the **reorg** case is unverified end-to-end. A `recordKey`/`recordWeight`
submitted for a boule block that is later reorged out lands in an EVM block that
may itself be reorged; reth's pool behavior across an EVM reorg of system txs is
not exercised. On restart, `recover_frontier` (`application.rs:541`) re-anchors
the *committed frontier* from reth's finalized head, but the **predeploy effects**
(rotation/endpoint/param/governance) are explicitly *not* backfilled over
self-synced gaps (`application.rs:202-208`) — only staking is
(`backfill_self_synced_gap`, `application.rs:483`). A rotation/governance/param
event in a self-synced gap is **silently dropped**; the doc-comment claims this is
"recoverable (the submitter re-submits)", but for a **governance `Approved`** the
"submitter" is the contract emitting once-per-proposal (`p.approved` one-shot,
`Governance.sol:96`) — a re-emit requires a *new* approval round, which may never
happen. So a self-synced gap can **silently lose an approved membership change**.

**Status:** open, **#766** (multi-node e2e: rotation, shared-nonce, reorg,
restart). The dropped-effect-over-gap concern is arguably a **NEW** correctness
sub-item beyond "test it" — see R9.

### R7 — Fail-closed behavior. MEDIUM (mostly safe; two sharp edges)

Mostly safe:
- `totalWeight == 0` (the #765 default): `weight*3 > 0*2` is false for any
  weight, so `approve` **never emits** — governance/param are inert, fail
  **closed** (`Governance.sol:105`, `Param.sol:110`). #765 tracks seeding genesis
  weights so the feature isn't inert by default.
- `keyAt` returning `< 128` bytes (no key at view): `Slashing` requires
  `key.length == 128` and reverts `"no registry key at view"`
  (`Slashing.sol:112`) — a slash with no settled key fails closed.
- Ed25519-only rotation (`new_bls_pubkey == None`): `record_key_for_rotation`
  returns `None`, nothing written (`registry.rs:168-171`) — see R8'.

Sharp edges:
- **`totalWeight` underflow risk if R1/R8 corrupt it.** `recordWeight` does
  `totalWeight - oldWeight + newWeight` (`Registry.sol:134`). On a real chain
  with Solidity ≥0.8 checked arithmetic this *reverts* on underflow rather than
  wrapping — safe — but a reverting `recordWeight` is *another* silent stale-write
  (the warn-and-continue path, R4). If `oldWeight` desynced from the true on-chain
  value (e.g. a forged `recordWeight` via R1), the legit proposer's next
  `recordWeight` can revert and the surface stays wrong. Not a memory-safety bug;
  a correctness/availability one downstream of R1.
- **`derive_*` swallow `eth_getLogs` errors** (`application.rs:140-148`,
  `218-229`): a transient RPC failure yields *no* effects/updates for that block
  and the height still advances. For staking this is backfilled; for
  rotation/endpoint/param/governance it is **not** (R6). Fail-open in the sense
  that the missed effect is just dropped.

**Status:** the genuinely-closed cases are fine; #765 covers the inert-default.
The "silent stale write on revert/RPC-error" pattern is the through-line of R4/R6.

### R8 — Shared system-account nonce races across rotating proposers. MEDIUM

`submit_system_call` fetches the system account's *pending* nonce per call
(`application.rs:603-607`) and submits sequentially within one commit
(`record_rotated_keys`/`record_validator_weights` await each,
`application.rs:297-318,348-369`). But the system account is **shared across all
proposers**, and proposer changes view-to-view. Two scenarios:
- Across a proposer rotation, the new proposer fetches the pending nonce
  independently; if the previous proposer's txs are still in-flight (not yet
  mined), nonces collide → stuck/replaced txs.
- Within R3: `recordKey` then `recordSettled` are submitted in that order but with
  *independent* nonce fetches; if they land in different EVM blocks the frontier
  can momentarily precede the key write.

Single-node `--dev` (the only tested config) never surfaces this.

**Status:** open, **#766** (explicitly lists "shared system-account nonce races").

### R8' — Ed25519-chain fallback (slashing is BLS/EIP-2537-only). LOW (intact)

Confirmed **not** silently broken on non-BLS chains:
- `record_key_for_rotation` yields `None` for an Ed25519-only rotation
  (`new_bls_pubkey == None`, `registry.rs:168-171`), so no `recordKey` is
  attempted and the registry simply holds no BLS history.
- `Slashing.submitEquivocation` requires a 128-byte EIP-2537 key and reverts
  otherwise (`Slashing.sol:112`) — so on an Ed25519 chain it cannot slash, but it
  also cannot **mis-**slash. Equivocation slashing is a BLS-chain capability;
  Ed25519 chains keep slashing in the consensus layer (the membership-jail path),
  which is unaffected.
- `validate_against_with_delay_and_scheme` rejects a BLS PoP on an Ed25519 chain
  (`reconfig.rs:357-360` doc + scheme check), so a BLS-chain payload replayed onto
  an Ed25519 chain is dropped.

**Status:** intact. No issue. (Worth a one-line explicit test that
`submitEquivocation` on an Ed25519-genesis chain reverts cleanly — minor.)

---

## 5. NEW risks (not covered by #763–#767)

### R9 — Submission/governance effects are silently dropped over an EL self-sync gap. NEW

`derive_predeploy_effects` is read **only on the normal per-block commit path**;
rotation/endpoint/param/**governance** events in blocks the EL executed via
background self-sync are **not** backfilled (`application.rs:202-208`), unlike
staking (`backfill_self_synced_gap`). For a `governance.Approved` (one-shot per
proposal, `Governance.sol:96`) the "submitter re-submits" recovery assumption does
**not** hold: re-emission needs a fresh approval round. A lagging/restarting node
(PART) that self-syncs past the block carrying an `Approved` can **silently lose an
approved membership change**, diverging its validator set from peers that
committed in order.

- Suggested issue: **"reth: backfill rotation/endpoint/param/governance effects
  over EL self-synced gaps (not just staking)"**
- priority: **high** · size: **medium**
- Rationale: a lost `Approved` is a membership/safety divergence, not a cosmetic
  miss; the once-per-proposal guard defeats the assumed re-submit recovery.

### R10 — System-account gas exhaustion / fee-policy is unowned operationally. NEW

R4 above: every-commit `recordSettled` + per-change writes drain genesis-only MVP
funding; on a real base-fee chain the account runs dry (registry silently stops:
`settledView` freezes, key/weight surface goes stale) or the hardcoded `max_fee =
2 gwei` (`system_account.rs:53`) is too low and writes stick pending. #763
mentions this as "couple here or split" but tracks **custody**, not the
fee/funding lifecycle. Split it so it isn't lost.

- Suggested issue: **"reth: define funding / fee-exemption / back-pressure for the
  system account (every-commit recordSettled drains it)"**
- priority: **high** · size: **medium**
- Acceptance: a fee-exempt system-call mechanism (or auto-refund), a documented
  base-fee-aware fee policy (not a hardcoded `max_fee`), and an alarm/metric when
  the system account stops landing writes (so the silent-stale failure is
  observable).

### R11 — `recordSettled` is submitted before the matching `recordKey` is known-executed. NEW (sub-risk of #767, but a concrete code fix)

Even granting #767's lag invariant, within a single commit the proposer submits
`recordKey` and `recordSettled` as **separate pool txs with independent nonces**
(`application.rs:858-862`), so "ordered last" is a *submission* ordering, not an
*execution* one. If they land in different EVM blocks (or out of order under R8),
`settledView` can reach a view whose key write hasn't executed.

- Suggested issue: **"reth: make recordSettled lag the observed execution of this
  block's recordKey (don't rely on submission order)"**
- priority: **medium** · size: **small**
- Could be folded into #767, but it's a distinct, concrete code change (gate
  `recordSettled(view)` on having *observed* the relevant `recordKey` executed,
  or advance the frontier conservatively by a lag margin).

---

## 6. Summary table

| Risk | Title | Severity | Mitigated? | Issue |
|------|-------|----------|------------|-------|
| R1 | Public system-account key → forge registry (slash honest / skew weights / move frontier) | CRITICAL | No (custody) | #763 |
| R2 | Forged-quorum approval (no msg.sender↔validator binding); event trusted | CRITICAL | No | #764 |
| R3 | settledFrontier exactness assumes unenforced EL-lag ≤ v_eff | HIGH | No | #767 |
| R4 | System account runs dry → registry silently stops | HIGH | No | #763 (partial) → **R10 NEW** |
| R5 | Event spoofing / log parsing | LOW | Yes (parser robust) | — |
| R6 | Reorg / restart of proposer write path | MEDIUM | Partial (idempotency) | #766 / **R9 NEW** |
| R7 | Fail-closed behavior | MEDIUM | Mostly yes | #765 (inert default) |
| R8 | Shared system-account nonce races | MEDIUM | No | #766 |
| R8' | Ed25519-chain fallback | LOW | Yes (intact) | — |
| R9 | Submission/governance effects dropped over self-sync gap | HIGH | No | **NEW** |
| R10 | System-account funding/fee policy unowned | HIGH | No | **NEW** |
| R11 | recordSettled not gated on recordKey execution | MEDIUM | No | **NEW** (sub of #767) |

**Bottom line.** The two CRITICALs (R1, R2) share one root — no on-chain
validator identity — and gate everything else: with R1 unfixed, the writer gate,
the slashing key-source, and the weight surface are *not trustworthy on a real
deployment*, regardless of the access control being structurally present. The
log-parsing and fail-closed layers are solid; the remaining gaps are
distributed-systems correctness (R3/R6/R8/R9/R11) and operational sustainability
(R10), several of which single-node `--dev` testing cannot surface.
