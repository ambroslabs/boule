# Prague bump — finalization on a live reth

This crate's chain moved from **Cancun-at-genesis** to **Prague-at-genesis** to
unlock the EIP-2537 BLS12-381 precompiles needed by the slashing precompile
(#732). The code half of that bump is done **in this PR**:

- `config.pragueTime = 0` and a `blobSchedule.prague` entry in `genesis.json`.
- `engine.rs` drives the Prague **Engine API V4** methods: `getPayloadV4` and
  `newPayloadV4` (which gains the `executionRequests` argument, EIP-7685).
  `forkchoiceUpdatedV3` is unchanged across Prague. This chain triggers **no**
  execution requests (its staking is the custom predeploy #655, not the beacon
  deposit contract; no EL withdrawals/consolidations), so `executionRequests`
  is always `[]`.
- The fixture-based unit tests were updated to the V4 method names and pass.

## What still needs a live Prague reth (the droplet half)

The unit tests use **recorded fixtures** (`fixtures/01-04*.json`) and **pinned
hashes** (`RETH_GENESIS`, `BLOCK1`, `BLOCK1_STATE_ROOT` in `engine.rs` /
`application.rs`). Those were recorded against a **Cancun** reth and cannot be
regenerated in CI (there is no live EL there). They test the *driver* logic, not
reth's actual output, so they stay green — but the values are no longer
byte-accurate for a Prague chain. Before running a real Prague chain:

1. **reth version.** Confirm the reth binary on `PATH` activates Prague.
   `run-reth.sh` currently pins **reth v2.2.0**; verify that release honors
   `pragueTime` (Pectra shipped on Ethereum mainnet 2025-05, so a 2025+ reth
   should — confirm with `reth --version` and a test `reth init`).

2. **Prague system predeploys.** A valid Prague chain expects the system
   contracts to exist: EIP-2935 (historical block hashes,
   `0x0000F90827F1C53a10cb7A02335B175320002935`), EIP-7002
   (`0x00000961Ef480Eb55e80D19ad83579A64c007002`), EIP-7251
   (`0x0000BBdDc7CE488642fb579F8B00f3a590007251`). Check whether your reth
   version **injects** these for a custom Prague genesis or **requires** them in
   `alloc`; if required, add them (canonical runtime bytecode from the EIPs /
   `reth init` output). They were intentionally **not** embedded here because
   their exact bytecode is reth-version-specific and unverifiable without a live
   reth — embedding a wrong blob is worse than adding the verified one on the
   droplet.

3. **Regenerate the genesis hash + golden fixtures.** Run a single-validator
   Prague chain (see `node-demo.md`) and re-record:
   - the genesis block hash → `RETH_GENESIS` / `engine.rs::GENESIS`,
   - block 1's hash + post-state root → `BLOCK1` / `BLOCK1_STATE_ROOT`,
   - the four `engine_*` responses (`forkchoiceUpdatedV3(attrs)`,
     `getPayloadV4`, `newPayloadV4`, `forkchoiceUpdatedV3(final)`) →
     `fixtures/01-04*.json`.

   Then re-run `cargo test -p boule-reth` to confirm the driver still parses the
   real Prague responses.

4. **blobSchedule.prague.** The `{target: 6, max: 9, baseFeeUpdateFraction:
   5007716}` values are the canonical Pectra (EIP-7691) ones; confirm your reth
   accepts them.

Once the chain runs green on a droplet, the BLS slashing precompile (#732b) can
land on top — a Solidity predeploy that verifies a BLS12-381 equivocation proof
via the now-available EIP-2537 precompiles.
