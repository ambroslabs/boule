# Running a single-validator reth chain

Stands up **one boule validator driving a reth execution layer** over the
Engine API, then sends an EVM transfer through consensus.

> Architecture: consensus orders opaque EVM execution payloads (1 boule
> block = 1 payload). The leader asks reth to build a payload
> (`forkchoiceUpdatedV3` + `getPayloadV3`); at commit every node executes
> it (`newPayloadV3`) and finalizes (`forkchoiceUpdatedV3`
> head=safe=finalized). Deferred-execution model. Engine API V3,
> Cancun-at-genesis. The reth backend lives in `boule-reth` and plugs into
> consensus through the async `Application` seam; the node opts in via the
> `reth` cargo feature.

## Scope

This is the **single-validator** path. It is correct for one validator on
a **fresh start**. Not yet supported:

- **Multi-validator** — a rotated leader building on a not-yet-committed
  parent needs that parent's payload registered in its own reth, which
  requires registering payloads on proposal-receipt (a follow-up).
- **Restart** — the reth `Application` tracks its committed frontier in
  memory and starts at genesis, so restarting a node against an
  already-advanced reth is not yet reconciled. Run from a fresh datadir.
- **State-sync** — a fresh joiner cannot reconstruct reth's world state
  from a consensus snapshot; it needs reth's own state-sync.

## 0. Prerequisites

- `reth` v2.2.0 on `PATH`, plus `openssl` and `foundry` (`cast`).
- Build the node binary **with the reth feature**:
  ```
  cargo build -p boule-cli --features reth
  ```
  This produces the `boule` binary; the standard build (no feature) omits
  the reth backend entirely.

## 1. Start reth (terminal 1, leave running)

```
crates/boule-reth/run-reth.sh
```

Engine API on `:8551` (JWT generated at `crates/boule-reth/jwt.hex` on
first run), eth RPC on `:8545`, no internal mining. The datadir is
recreated each run so genesis is always at height 0.

## 2. Read reth's genesis state root

```
cast rpc --rpc-url http://127.0.0.1:8545 eth_getBlockByNumber 0x0 false | jq -r .stateRoot
```

Copy that value (without the `0x`) into `genesis_seed_hex` below. The node
verifies the bridge at startup: if `genesis_seed_hex` does not equal reth's
genesis state root it refuses to start and prints the exact value to set.

## 3. Init the node key + get the NodeId (terminal 2)

```
cargo run -p boule-cli --features reth -- init --config ./boule-reth.toml
```

Mints `./boule/node.key` and prints the node's base58 NodeId. Put that into
`[consensus] validators` below.

## 4. Config — `boule-reth.toml`

```toml
[node]
listen_addr = "127.0.0.1:7000"

[node.identity]
backend = "file"
path    = "./boule/node.key"

[api]
listen_addr = "127.0.0.1:8000"

[consensus]
validators       = ["<YOUR-NODE-ID-FROM-STEP-3>"]
genesis_seed_hex = "<RETH-GENESIS-STATE-ROOT-FROM-STEP-2 without 0x>"
storage_dir      = "./boule/consensus"
timeout_base_ms  = 500
timeout_max_ms   = 5000
# A single validator self-certifies instantly, so without a floor it would
# produce empty blocks as fast as the loop spins. 1s gives a steady,
# MetaMask-friendly block time.
min_block_interval_ms = 1000

[consensus.application]
backend         = "reth"
engine_url      = "http://127.0.0.1:8551"
eth_url         = "http://127.0.0.1:8545"
jwt_secret_path = "crates/boule-reth/jwt.hex"
fee_recipient   = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
```

## 5. Run the validator

```
cargo run -p boule-cli --features reth -- start --config ./boule-reth.toml
```

It bridges genesis (consensus `genesis_seed_hex` must equal reth's genesis
state root — it bails with the right value otherwise), then begins
proposing: each block asks reth to build a payload and commits it.

## 6. Send an EVM transfer and watch it land

Prefunded dev account (anvil key #0):
`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`.

```
PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
cast send --rpc-url http://127.0.0.1:8545 --private-key $PK \
  0x000000000000000000000000000000000000dEaD --value 1ether

# After the next block commits, the tx is in a block and the balance moved:
cast balance --rpc-url http://127.0.0.1:8545 0x000000000000000000000000000000000000dEaD
cast block-number --rpc-url http://127.0.0.1:8545
```

The tx enters reth's own pool; the leader's next `getPayload` includes it,
and the block commits through consensus. The block number advances over
time as boule drives reth. A MetaMask wallet pointed at `:8545`
(chain-specific settings from `genesis.json`) can deploy and call
contracts the same way.

## Re-capturing the test fixtures

`boule-reth`'s offline tests replay golden Engine API exchanges in
`fixtures/`. To re-capture them against a live reth (e.g. after a reth
version bump), point an `HttpTransport` at a fresh reth with a
`fixtures_dir` set — see `HttpTransport::new` and the recording branch in
`transport.rs`.
