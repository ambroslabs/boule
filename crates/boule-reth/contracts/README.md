# boule-reth contracts

## `Staking.sol` — validator-staking predeploy (#655)

The EVM-native interface for validator staking on the reth backend. Users
call `deposit(bytes32 nodeId)` / `withdraw(bytes32 nodeId, uint256 amount)`
with ordinary EVM transactions; the contract emits `Deposit` / `Withdraw`
events. boule reads those events from each committed block (via
`eth_getLogs`) and drives its validator set from them — the contract is a
pure event emitter, the authoritative stake balance lives consensus-side
(`BondedStakeLedger`, #654).

Deployed as a **genesis predeploy** at a fixed address (the beacon-deposit
pattern): the compiled runtime bytecode is embedded in `../genesis.json`
under `alloc`, so no deployment transaction is needed.

| | |
|---|---|
| Address | `0x0000000000000000000000000000000000000b0e` |
| `Deposit(bytes32,uint256)` topic0 | `0x98e783c3864bbf744a057ef605a2a61701c3b62b5ed68b3745b99094497daf1f` |
| `Withdraw(bytes32,uint256)` topic0 | `0x4591ca0897d0d8e83f7153dfe0b2912125672084ab8d84be59ee13240a1778bc` |
| `deposit(bytes32)` selector | `0xb214faa5` |
| `withdraw(bytes32,uint256)` selector | `0x040cf020` |

These identifiers are mirrored as constants in `src/staking.rs`; a unit test
pins the address to the genesis account.

### Reproducing the bytecode

Compiled with **solc 0.8.24** (runtime/deployed bytecode):

```sh
solc --bin-runtime contracts/Staking.sol
# or, without a system solc:
pip install py-solc-x --break-system-packages
python3 -c "import solcx; solcx.install_solc('0.8.24'); \
  print(solcx.compile_files(['contracts/Staking.sol'], output_values=['bin-runtime'], solc_version='0.8.24'))"
```

Paste the `bin-runtime` hex (prefixed with `0x`) into the predeploy account's
`code` field in `genesis.json`. If the contract changes, update both the
bytecode and the constants in `src/staking.rs`.

## `Rotation.sol` — validator key-rotation predeploy (#730)

The EVM-native submission path for validator signing-key / operator-key
rotations on the reth backend (milestone #4). A validator rotates by sending an
ordinary EVM transaction to `submitRotation(bytes32 validator, bytes
rotationCommand)`, where `rotationCommand` is the **already-encoded, dual-signed**
boule rotation command (`DualSignedRotation::encode_command()` or an
operator/cancel variant). The contract is a pure event emitter; boule reads the
`RotationSubmitted` event from each committed block (via `eth_getLogs`), turns
it into a `ValidatorEffect::KeyRotation` on the widened `CommitResult` (#727),
and re-materialises the command into a block — where the existing rotation path
verifies the signatures and schedules the `v_eff` key swap. The
`RotatableSigner` / key-history mechanism (#312/#258) is unchanged; only the
submission path moves onto the EVM, replacing the bespoke rotation mempool tx.

> [!NOTE]
> The EVM never interprets `rotationCommand`; consensus validates the command's
> tag and self-attestation signatures when it materialises the effect. The
> submitter must set `v_eff` far enough ahead to clear the execution lag plus
> the validation floor (a too-soon rotation is rejected at apply, not unsafe).

| | |
|---|---|
| Address | `0x0000000000000000000000000000000000000b0f` |
| `RotationSubmitted(bytes32,bytes)` topic0 | `0xde7f9466fbeb5e013694b9e04812cc106a0a764766c202e2f88a480ee27120d1` |
| `submitRotation(bytes32,bytes)` selector | `0x37fe3f23` |

These identifiers are mirrored as constants in `src/rotation.rs`; unit tests
pin the address, topic, and selector to the genesis account's bytecode.

### Reproducing the bytecode

Same toolchain as `Staking.sol` above (**solc 0.8.24**, `bin-runtime`):

```sh
python3 -c "import solcx; solcx.install_solc('0.8.24'); \
  print(solcx.compile_files(['contracts/Rotation.sol'], output_values=['bin-runtime'], solc_version='0.8.24'))"
```

Paste the `bin-runtime` hex (prefixed with `0x`) into the predeploy account's
`code` field in `genesis.json`. If the contract changes, update both the
bytecode and the constants in `src/rotation.rs`.
