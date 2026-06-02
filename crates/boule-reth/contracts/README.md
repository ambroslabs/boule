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
