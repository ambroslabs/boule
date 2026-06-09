# Running a single-validator reth chain

Stands up **one boule validator driving a reth execution layer** over the
Engine API, then sends an EVM transfer through consensus.

> Architecture: consensus orders opaque EVM execution payloads (1 boule
> block = 1 payload). The leader asks reth to build a payload
> (`forkchoiceUpdatedV3` + `getPayloadV4`); at commit every node executes
> it (`newPayloadV4`) and finalizes (`forkchoiceUpdatedV3`
> head=safe=finalized). Deferred-execution model. Engine API V4,
> Prague-at-genesis (see `PRAGUE-MIGRATION.md` for the live-reth
> finalization steps). The reth backend lives in `boule-reth` and plugs into
> consensus through the async `Application` seam; the node opts in via the
> `reth` cargo feature.

## Scope

This is the **single-validator** path. Not yet supported:

- **Multi-validator** — a rotated leader building on a not-yet-committed
  parent needs that parent's payload registered in its own reth, which
  requires registering payloads on proposal-receipt (a follow-up).
- **State-sync** — a fresh joiner cannot reconstruct reth's world state
  from a consensus snapshot; it needs reth's own state-sync.

On **restart** the node reconciles the reth `Application`'s committed frontier
with reth's persisted finalized head, so a node restarted against an
already-advanced reth resumes with the correct lagged `committed_state_root`
(no fresh datadir required).

## 0. Prerequisites

- `solc` (the predeploy genesis is compiled from source by `boule-reth`'s
  `build.rs`), plus `openssl`, `curl`, `jq`, and `foundry` (`cast`). The custom
  execution layer (`boule-reth-node`) is built from source by `run-reth.sh` — no
  `reth` binary on `PATH` is needed.
- Build the node binary **with the reth feature**:
  ```
  cargo build -p boule-cli --features reth
  ```
  This produces the `boule` binary; the standard build (no feature) omits
  the reth backend entirely.

## 1. Start the execution layer (terminal 1, leave running)

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

### Multi-validator: peer the reths

For a multi-validator chain, set `reth_peers` to the **other** validators'
reth `enode://…` URLs:

```toml
[consensus.application]
backend     = "reth"
# … engine_url / eth_url / jwt_secret_path / fee_recipient as above …
reth_peers  = [
  "enode://<peer1-pubkey>@<peer1-host>:30304",
  "enode://<peer2-pubkey>@<peer2-host>:30305",
]
```

At startup the node connects its local reth to each peer via `admin_addPeer`
(so `run-reth.sh` enables the `admin` RPC namespace). Get a reth's enode with
`cast rpc --rpc-url <its eth_url> admin_nodeInfo | jq -r .enode` (or
`admin_nodeInfo` over JSON-RPC). Peering the validator reths is what makes:

- **tx-pool gossip** work — a tx submitted to *any* node's reth reaches every
  leader's pool, so it's included no matter which node receives it; and
- **EL self-sync** work — a behind or fresh reth backfills (snap/full) from its
  peers when consensus points it at a head it doesn't have yet.

Peering is best-effort: an unreachable peer is logged and skipped (reth keeps
retrying), so node startup never blocks on it.

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

## 7. Recovery: fresh and behind nodes

A node that joins from genesis, or restarts after losing its data, recovers in
two independent layers:

- **Consensus (CL).** boule catches its committed chain up over the network —
  by block-sync when the gap is within `block_retention_window`, or by
  snapshot-sync (then following live consensus) when it is further behind. The
  node ends up committed at the live tip without necessarily holding every
  intermediate block locally.
- **Execution (EL).** reth catches its EVM state up *itself* over devp2p. When
  consensus commits a block whose parent state reth doesn't have, the Engine
  API returns `SYNCING`; boule keeps driving `forkchoiceUpdated` (head = safe =
  `finalized`) so reth has a target, and reth backfills from its peers — **full
  sync** (re-execute bodies) or **snap sync** (download the state trie at a
  recent pivot, then execute forward). It needs the validator reths **peered**
  (§4); an unpeered reth has no one to backfill from and stays at genesis.

So peering is not just a steady-state nicety — it is what lets a fresh or
deeply-behind EL recover at all. With it, a node wiped past the retention
window rejoins end to end: consensus jumps to the tip and reth self-syncs up to
the same `stateRoot` the rest of the cluster agrees on.

### Trust model

Snap-downloaded state is **Merkle-verified against the pivot block's
`stateRoot`**: account ranges carry boundary proofs, storage verifies against
each account's `storageRoot`, bytecode against its `codeHash` — all chaining up
to `stateRoot`. A malicious EL peer can therefore only *withhold* state
(liveness), never *forge* it (safety). The single trusted input is the **pivot
`stateRoot`**, and boule supplies it: `forkchoiceUpdated(finalized = H)` names a
BFT-committed block whose header carries the consensus-agreed EVM commitment
(itself validated by the lagged deferred-root check). Unlike mainnet there is no
probabilistic pivot — finality is real.

Operator-supplied trust parameters:

- the **genesis validator set** (already required to join consensus), and/or
- an optional **weak-subjectivity checkpoint** — a recent finalized boule block
  a fresh joiner anchors to instead of trusting genesis alone. Configure it under
  `[consensus.weak_subjectivity_checkpoint]`:

  ```toml
  [consensus.weak_subjectivity_checkpoint]
  height = 1000000
  hash   = "<64-hex block hash at that height, from a trusted source>"
  ```

  The node then refuses to commit or recover any chain whose block at `height`
  does not hash to `hash` — fail-stop, so a fresh joiner cannot be walked onto a
  long-range fork. Unset (the default) is genesis-anchored. Trade-off: a stale
  checkpoint still anchors safety but leaves a longer recent prefix trusted on
  the validator set alone.

Liveness assumptions: at least one honest reth peer serving state, and a pivot
recent enough that non-archive peers still retain its state.

## 8. Multi-validator testnet

To bring up a whole reth-backed cluster — `N` boule validators, each driving its
own custom EL, peered so the EVM tx-pool gossips — use the deployment-artifact
generator `gen-testnet.sh` (it emits per-node configs + run tooling and is the
maintained multi-node path). See [`../../docs/join-testnet.md`](../../docs/join-testnet.md).

## Re-capturing the test fixtures

`boule-reth`'s offline tests replay golden Engine API exchanges in
`fixtures/`. To re-capture them against a live reth (e.g. after a reth
version bump), point an `HttpTransport` at a fresh reth with a
`fixtures_dir` set — see `HttpTransport::new` and the recording branch in
`transport.rs`.
