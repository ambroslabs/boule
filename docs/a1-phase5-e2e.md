# A1 Phase 5 — consumers + multi-node convergence e2e (#785)

The final A1 validation. A1's **write path** is complete and merged: the custom
EL (`boule-reth-node`) is the sole, keyless writer of the Registry predeploy at
`0x…0b12`, applying `recordKey` / `recordWeight` / `recordSettled` as
deterministic system calls from each block's `registryPayload` (#777/#788/#795).
Phase 5 validates the *other two* halves:

- **(a)** the **consumers** — the Slashing and Governance predeploys — read the
  **EL-written** registry correctly end-to-end, and
- **(b)** a 2-node boule+custom-EL cluster **converges** on a byte-identical
  Registry (the determinism claim, empirically).

Both were run on a single real boule validator (a) / two networked validators
(b), each driving a real `boule-reth-node` over the Engine API. Both PASS.

## Part (a) — slashing + governance against the EL-written registry

Harness: `crates/boule-reth/single-node-el-e2e.sh` (extends the cutover's e2e).
One real boule validator (sole proposer, BLS chain) drives the custom EL; the
genesis seeds the Registry with a dev validator set (`gen-genesis 4`: NodeId
`[i+1;32]`, BLS key from IKM `[i+1,0,…]`, weight `i+1`, Σ = 10), whose keys live
at `vEff = 0` (settled from genesis). Those genesis-seeded `keyAt`/`weightOf`
values are the **EL-written** registry surface the consumers read.

New helper bins:

- `gen-equivocation` (`boule-consensus`): forges a validator equivocation proof
  (two `Vote`s, same view, different blocks, both BLS-signed) in the EIP-2537
  encoding `Slashing.submitEquivocation` verifies, using the **same** dev-key
  derivation the genesis registry holds (`--seed`) — cross-checked against the
  `gen_slashing_vectors` ground truth. A `--digest` mode signs an arbitrary
  approval digest with that same key (the Governance approval signature).
- `el-e2e-ops` gains `submit-equivocation`, `gov-digest`, `gov-approve`,
  `gov-state`, `keccak256` (ABI-encoded via `alloy_sol_types::sol!`; the
  selectors are pinned to the library constants by a unit test).

### (a.1) Slashing emits against the EL-written key — PASS

```
keyAt(0x02…02, view 0) len = 128B            (the EL-written genesis-seeded key)
submitEquivocation(...) -> STATUS=1 SLASHED=1  ✓ Slashed emitted
above-frontier proof (view > settledView)    -> STATUS=0 SLASHED=0  ✓ reverted
```

The Slashing predeploy verified both BLS signatures **in-EVM against the
EL-written `keyAt`** (the EIP-2537 precompiles) and emitted `Slashed`. The
**`settledView` gate** correctly rejected a proof for a view above the frontier
(`"view not settled"`) even though a key exists there — proving the gate, read
from the EL-written `settledView()`, governs slashing.

boule's read side (`eth_getLogs` for `Slashed` → `StakeSource::slash` → `weight
0` jail) is unit-tested (`slashing::parse_slashed_logs`,
`application.rs` slash → `validator_updates`); the slashed dev validator is not
seated in *this* run's consensus set (only the minted sole proposer is), so the
on-chain emit + verify against the EL key is the load-bearing, EL-dependent claim
proven here.

### (a.2) Governance tallies the EL-written weights — PASS

```
totalWeight (EL-written) = 12                (dev Σ10 + the live validator's seated weight)
approve VD(w=4) -> tally=4   APPROVED=0       (4*3=12  ≤ 24)
approve VC(w=3) -> tally=7   APPROVED=0       (7*3=21  ≤ 24)
approve VB(w=2) -> tally=9   APPROVED=1   ✓   (9*3=27  > 24 = ⅔ crossing)
isApproved = 1, Approved carried the exact reconfig command
```

Each approval carried the validator's **own BLS signature** over the contract's
`approveDigest` (verified in-EVM against `Registry.keyAt(validator,
settledView())`), and `Governance.approve` accrued **exactly the EL-written
`weightOf`** for each (tally 4 → 7 → 9, the cumulative dev weights). `Approved`
emitted **exactly** when the running weight crossed a strict ⅔ of the EL-written
`totalWeight` — i.e. the weighted tally read the EL weight surface. The carried
command is opaque to the EVM; boule re-materialises it (the read path is
exercised by the `app_validator_updates_minted_reconfig` events in the log).

## Part (b) — multi-node convergence — PASS (ran, not blocked)

Harness: `crates/boule-reth/multi-node-el-e2e.sh`. Two real boule validators,
**each with its own `boule-reth-node` EL** (EL1 8545/8551, EL2 8555/8561),
peered over TCP into one BLS chain (a real **2-of-2** quorum). The testnet driver
does not wire reth, so this hand-stands-up the cluster: it mints 2 node + 2 BLS
keys, derives the **joint** chain-bound BLS PoPs over the whole set (new
`gen-bls-genesis --multi`, since the single-validator chain_id cannot serve a
2-validator set), writes mutual `[[peers]]` configs, and points each node at its
own EL.

The cluster connected (`connected to peer …`), formed a quorum, and committed
blocks over the network. After a stake deposit (for NID1, via EL1) and a BLS
rotation committed through consensus, **both** ELs' Registries — read at a
**common pinned EVM height** (so `settledView`, which advances every block, is
compared at one point rather than raced across two live nodes) — were
byte-identical:

```
EL1@15: weightOf=4 totalWeight=14 settledView=11 keyAtLen=128
EL2@15: weightOf=4 totalWeight=14 settledView=11 keyAtLen=128
  ✓ byte-identical keyAt / weightOf / settledView on both nodes
```

This empirically confirms the determinism claim across two **independently
executing** ELs driven by two **networked** consensus nodes — the EL-applied
registry write is a pure function of the committed block, so every replica
mirrors it identically.

### Note on the `settledView` sampling

`settledView` advances every committed block, so a naive `latest`-vs-`latest`
read of two live, independently-advancing nodes can differ by ±1 purely from
sampling skew (observed in the first run: 316 vs 317). The harness reads both at
the same pinned height; `keyAt`/`weightOf` are stable once written and match on
`latest` regardless.

### Complementary proof

`crates/boule-reth/drive-custom-el-2inst.sh` (#793) is the other half of the
determinism evidence: it drives two ELs **directly** over the Engine API (A
builds a payload, B verifies the *same* sealed payload from `extra_data` alone)
and asserts identical block hashes **and** identical `0x…0b12` state. Re-run
green here. Together with the networked run above, both the build→verify and the
full networked-quorum paths are shown to converge.

## Running it

```sh
export SOLC=~/.solcx/solc-v0.8.24 \
       BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/15/include"
bash crates/boule-reth/single-node-el-e2e.sh   # part (a)
bash crates/boule-reth/multi-node-el-e2e.sh    # part (b)
bash crates/boule-reth/drive-custom-el-2inst.sh  # build→verify determinism
```

Each script tears down every EL/boule process it starts (no orphans).
