# boule + reth node image

One image that runs a boule consensus node and its custom reth execution layer
(`boule-reth-node`) side by side. boule orders blocks; reth executes the EVM
payloads. The image ships the **binaries + orchestration**; the **chain** is
supplied at runtime, so the same image runs any node — a validator, a full node,
or one-of-N in a cluster.

## Build

Context is the repo root (the build compiles `boule-reth-node`'s reth-SDK tree,
so the first build is slow):

```sh
docker build -f docker/Dockerfile -t boule-node .
```

## Run a single-validator dev chain (zero config)

With nothing mounted, the entrypoint bootstraps a one-validator chain on first
start:

```sh
docker run --rm -p 8545:8545 -p 8000:8000 boule-node
```

- `:8545` — EVM JSON-RPC (`eth_*`); submit transactions here.
- `:8000` — boule node API (status/health).

Persist the generated chain + state across restarts by mounting volumes:

```sh
docker run --rm -p 8545:8545 -p 8000:8000 \
  -v boule-chain:/chain -v boule-data:/data boule-node
```

## Run an arbitrary node (mount a chain)

Provide the chain artifacts under `CHAIN_DIR` (default `/chain`) and bootstrap is
skipped — the node runs exactly what you mount:

```
/chain/
  genesis.json   # reth chainspec (predeploys + seeded Registry weights)
  jwt.hex        # Engine API CL<->EL secret
  node.toml      # boule config: identity, [consensus], [consensus.application]
  node.key       # (referenced by node.toml)
  bls.key        # (referenced by node.toml)
```

```sh
docker run --rm -p 8545:8545 -p 8000:8000 \
  -v /path/to/node-i:/chain -v boule-data-i:/data boule-node
```

For a multi-node cluster, generate per-node artifact dirs with
`crates/boule-reth/gen-testnet.sh` and run one container per node, each mounting
its own dir. Cross-node reth peering is driven by `reth_peers` in each
`node.toml` (boule calls `admin_addPeer` at startup), so expose `30303` and use
reachable enodes there.

## Environment

| Var | Default | Purpose |
| --- | --- | --- |
| `CHAIN_DIR` | `/chain` | genesis, JWT, keys, `node.toml` |
| `DATA_DIR` | `/data` | reth datadir + consensus storage (mutable) |
| `GENESIS` / `JWT` / `BOULE_CONFIG` | under `CHAIN_DIR` | individual path overrides |
| `EL_HTTP_ADDR` / `EL_HTTP_PORT` | `0.0.0.0` / `8545` | eth RPC bind |
| `EL_AUTHRPC_PORT` | `8551` | Engine API (loopback only) |
| `EL_P2P_PORT` | `30303` | reth p2p |
| `RETH_EXTRA_ARGS` | — | extra flags passed to `boule-reth-node node` |
| `BOOTSTRAP` | `auto` | `auto` = make a single-validator chain if `CHAIN_DIR` is empty; `never` = require a mounted config |

## Notes

- The entrypoint starts the EL, waits for its RPC, then `exec`s boule (which
  queries the EL's genesis at startup and does **not** retry). Run with
  `docker run --init` for a tini reaper if you want the EL reaped on boule exit.
- Bootstrapped keys land under `CHAIN_DIR`. With a named volume they persist and
  are unique to that deployment; without one they're regenerated each start.
