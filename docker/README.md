# boule Docker image

A minimal, single-binary image: the ONE `boule` binary (consensus + the custom
reth execution layer **in-process**), nothing else. No `entrypoint.sh`, no
bootstrap script, no wait-loop — reth is linked into the same process, so a dev
chain is a single command.

The image's `ENTRYPOINT` is `boule`, so anything after the image name is a
`boule` subcommand (`node`, `init`, `genesis`, `key`, `config`, …).

## Build

The bundle path-depends on its sibling crates, so build from the **repo root**
with the Dockerfile under `docker/`:

```sh
docker build -f docker/Dockerfile -t boule .
```

The builder installs the pinned solc 0.8.24 (boule-reth's `build.rs` compiles the
EVM predeploy genesis from source — the bytecode is never committed) plus
clang/libclang for reth's `mdbx-sys` bindgen. The reth dependency tree is large,
so the first build is slow (~several minutes); a BuildKit cache mount keeps the
cargo registry and the workspace `target/` warm across rebuilds.

## Zero-config dev chain

`boule node --dev` bootstraps a single-validator chain entirely in-process — it
mints a dev node key + BLS key, builds a seeded genesis, launches reth, mints the
chain-bound BLS proof-of-possession at reth's genesis state root, and runs
consensus. No provisioning, no flags required:

```sh
docker run --rm -p 8545:8545 boule node --dev
```

State lives in a temp dir inside the container (wiped on exit). To keep it across
restarts, mount a volume and point `--datadir` at it:

```sh
docker run --rm -p 8545:8545 -v boule-dev:/data boule node --dev --datadir /data
```

Confirm blocks are committing via the public `eth_*` RPC on `:8545`:

```sh
curl -s http://localhost:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
# => {"jsonrpc":"2.0","id":1,"result":"0x.."}  # advances over time
```

The dev genesis prefunds the canonical dev account
`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` (also the block fee recipient), so
you can send transactions immediately.

### Dev flags

| flag             | default            | meaning                                  |
| ---------------- | ------------------ | ---------------------------------------- |
| `--datadir DIR`  | temp dir (wiped)   | reth state + minted keys + dev genesis   |
| `--http.port N`  | `8545`             | public `eth_*` HTTP RPC port             |
| `--authrpc.port N` | `8551`           | Engine API TCP port (reth binds it)      |
| `--port N`       | `0` (OS-picked)    | devp2p listener port                     |
| `--http.api S`   | `eth,net,web3,txpool,admin` | exposed RPC modules             |

`--dev` is for **local development only** — it uses a deterministic, insecure key
setup. Do not expose it publicly.

## Custom chain (multi-step recipe)

For a real chain you provision the genesis + keys yourself, then run `boule node`
against them. Mount a host directory as the work dir and drive the subcommands
through the same image (the steps mirror the in-process flow `--dev` automates):

```sh
# A host directory for the chain's genesis, keys, and config.
mkdir -p chain && WORK=$PWD/chain

# 1) Seeded reth genesis (Registry predeploy + dev validator weights).
docker run --rm -v "$WORK:/w" boule \
  genesis dev --validators 4 --out /w/genesis.json

# 2) Mint a node key (writes /w/node.key, prints the NodeId).
docker run --rm -v "$WORK:/w" boule \
  init --config /w/config.toml      # author config.toml with a [node.identity] file backend at /w/node.key

# 3) Read reth's genesis state root, then mint the validator's chain-bound BLS
#    PoP at that root (the seed the chain binds to):
docker run --rm -v "$WORK:/w" boule \
  genesis bls-pop --genesis-seed <ROOT> \
  --validator <NODE_ID>:/w/bls.key --allow-insecure-key-perms

# 4) Run the node against the mounted genesis + config + datadir:
docker run --rm -p 8545:8545 -v "$WORK:/w" boule \
  node -c /w/config.toml --chain /w/genesis.json --datadir /w/reth
```

The exact single-validator provisioning sequence is captured end-to-end in
`crates/boule-bundle/tests/bundle_smoke.rs` (`single_validator_commits_blocks`).
For the zero-config path, just use `node --dev`.
