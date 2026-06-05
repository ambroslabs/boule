# Joining the boule testnet (run a full node)

This runbook is for an **external operator** who wants to run a
**non-validating full node** that follows the trusted validator set, applies
every committed block, and serves its own execution-layer (reth) JSON-RPC. A
full node never proposes, votes, or rotates leadership — it is the read/RPC
witness of the chain (`[consensus] full_node = true`, #802/#812).

It also covers, at the end, how the testnet itself is generated and stood up
(`gen-testnet.sh`) — the validator side — so you can reproduce the whole
topology locally.

> **Architecture recap.** boule (HotStuff BFT) orders opaque EVM execution
> payloads; reth executes them (1 boule block = 1 EVM payload, deferred
> execution). A full node runs the same two processes a validator does —
> a local `boule-reth-node` reth EL + the `boule` consensus node — it just
> doesn't sign. See `crates/boule-reth/node-demo.md` for the EL mechanics.

## 0. What the operators of the trusted set must give you

To join, you need four things from the testnet operators (all public):

1. **`genesis.json`** — the seeded genesis (validator weights + chain-id +
   prefund). Must be byte-identical to what the validators booted, or your
   reth's genesis state root won't match and your node refuses to start.
2. **The EVM chain-id** — it's in `genesis.json` under `config.chainId`
   (the generator defaults to `767676`).
3. **The `genesis_seed_hex`** — reth's genesis EVM state root, the
   consensus↔EL genesis seed. It's the same on every node; the operators
   publish it (or you read it from your own reth's block 0, step 3).
4. **Seed peers** — the validators' `host:p2p_port` + base58 NodeId pairs
   (the `[[peers]]` block), and ideally their reth `enode://` URLs.

## 1. Prerequisites

- `reth` v2.2.0 on `PATH` (the EL), plus `openssl`, `jq`, `curl`.
- The two boule binaries, **built with the reth feature**:
  ```sh
  cargo build -p boule-cli --features reth            # produces `boule`
  cargo build -p boule-reth-node                      # produces the reth EL node
  ```
  Put both on `PATH` (or reference them by absolute path below).

## 2. Mint your node identity

Your full node needs its own Ed25519 (TLS) network identity. Its base58 NodeId
is your address on the p2p overlay.

```sh
cat > full.init.toml <<'EOF'
[node]
listen_addr = "0.0.0.0:7010"
[node.identity]
backend = "file"
path = "/etc/boule/full.key"
[api]
listen_addr = "0.0.0.0:8010"
EOF

boule init --config full.init.toml      # prints "NodeId = <base58>"
```

You do **not** mint a BLS key — only validators have one. Give the trusted set
your NodeId + `host:7010` if they pin inbound peers (optional on a TOFU testnet).

## 3. Start your reth EL on the trusted genesis

Boot reth on the **operators' `genesis.json`** (not a regenerated one):

```sh
openssl rand -hex 32 > /etc/boule/jwt.hex
boule-reth-node node \
  --chain /etc/boule/genesis.json --datadir /var/lib/boule/reth \
  --authrpc.addr 127.0.0.1 --authrpc.port 8551 --authrpc.jwtsecret /etc/boule/jwt.hex \
  --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3 \
  --port 30330 --ipcdisable &
```

> **Never expose reth's HTTP RPC (`:8545`) or Engine API (`:8551`) to the
> internet.** Both are bound to `127.0.0.1` above on purpose. The Engine API is
> JWT-auth'd but is not a public surface; reth's HTTP RPC has no method-level
> allow-list (raw `admin_*`/`txpool_*`/`debug_*` would be reachable). The
> **only** public eth ingress is the `eth-rpc-proxy` (step 6), which forwards a
> read-only-plus-`eth_sendRawTransaction` allow-list. That is why `--http.api`
> is `eth,net,web3` (no `txpool,admin`) and `--http.addr` is loopback.

Confirm your genesis state root matches the published `genesis_seed_hex`:

```sh
curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' \
  | jq -r '.result.stateRoot'
```

If this differs from the operators' `genesis_seed_hex`, your `genesis.json` is
wrong — stop and get the right one. **boule refuses to start on a mismatch.**

## 4. Write your full-node config

```toml
# /etc/boule/full.toml
[node]
listen_addr = "0.0.0.0:7010"
[node.identity]
backend = "file"
path = "/etc/boule/full.key"

[api]
# Public, read-only observability surface — metrics / health / ready only.
listen_addr = "0.0.0.0:8010"
[api.admin]
# Privileged + internal-state surface (mempool submit, /consensus/status,
# /peers). Loopback-only; add auth_token_env in prod (#823).
listen_addr = "127.0.0.1:9010"

# Seed peers: the trusted validators (host:p2p_port + their base58 NodeId).
# Get these from the operators. A static list is fine for a trusted testnet.
[[peers]]
addr = "validator-0.testnet.example:7001"
node_id = "<VAL0_NODE_ID>"
[[peers]]
addr = "validator-1.testnet.example:7002"
node_id = "<VAL1_NODE_ID>"
# ... one [[peers]] per validator (and any other full nodes you want to mesh).

[consensus]
# The trusted validator set — byte-identical to the validators' configs.
validators = ["<VAL0_NODE_ID>", "<VAL1_NODE_ID>", "<VAL2_NODE_ID>"]
# THE key line: follow the committee without joining it.
full_node = true
signature_scheme = "bls_aggregated"
genesis_seed_hex = "<GENESIS_STATE_ROOT_FROM_STEP_3>"
storage_dir = "/var/lib/boule/consensus"
timeout_base_ms = 1000
timeout_max_ms = 8000

# The validators' BLS rows — same table the validators carry. Get from operators.
[[consensus.validators_bls]]
node_id = "<VAL0_NODE_ID>"
bls_pubkey = "<VAL0_BLS_PUBKEY_HEX>"
bls_pop = "<VAL0_BLS_POP_HEX>"
# ... one per validator.

[consensus.application]
backend = "reth"
engine_url = "http://127.0.0.1:8551"
eth_url = "http://127.0.0.1:8545"
jwt_secret_path = "/etc/boule/jwt.hex"
fee_recipient = "0x0000000000000000000000000000000000000000"
# The validators' reth enode:// URLs, so your EL gossips txs + self-syncs.
reth_peers = ["enode://<VAL0_RETH>@validator-0.testnet.example:30330", "..."]
```

> A full node sets `full_node = true` and its NodeId is **not** in
> `validators`. (A node whose NodeId *is* in `validators` but which sets the
> flag is rejected at startup — that misconfiguration is caught early.)

## 5. Start the full node and verify it is following

```sh
boule start --config /etc/boule/full.toml
```

It logs its role at boot (`role is full`). Verify it is following + serving RPC:

```sh
# (a) boule is healthy + ready (follower readiness = committed progress).
#     /health, /ready, /metrics are the PUBLIC surface (:8010).
curl -s http://127.0.0.1:8010/health  ; echo
curl -s http://127.0.0.1:8010/ready   ; echo
# /consensus/status and /peers expose full internal consensus state, so they
# moved to the ADMIN listener (:9010, loopback / bearer-auth) — not public (#823).
curl -s http://127.0.0.1:9010/consensus/status | jq '{view, committed_height}'

# (b) your EL is following the committee's blocks (height climbs over time).
curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | jq -r '.result'

# (c) the chain's weighted-quorum surface is visible (Registry @ 0x…0b12):
#     totalWeight() — selector 0x96c82e57 — should be the Σ of validator weights.
curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000000b12","data":"0x96c82e57"},"latest"]}' \
  | jq -r '.result'
```

When `committed_height` and the EL `eth_blockNumber` both climb and track the
validators, your full node is following the testnet and serving RPC. Submit
EVM transactions via the public proxy (step 6) — they gossip to the validators
via `reth_peers` and land in a committed block.

## 6. Expose a public eth RPC (and optional faucet)

reth's `:8545` is loopback-only, so to let the public submit transactions and
read chain state, run the `eth-rpc-proxy` in front of it as the **single public
ingress**. It forwards only the allow-listed read-only + `eth_sendRawTransaction`
surface (no `admin_*`/`txpool_*`/`debug_*`), with batch/body caps and per-IP
rate limiting:

```sh
# Public on :8547, forwarding to reth's loopback RPC. This — not :8545 — is
# what you publish / put behind your LB.
ETH_RPC_PROXY_LISTEN_ADDR=0.0.0.0:8547 \
ETH_RPC_PROXY_BACKEND_URL=http://127.0.0.1:8545 \
  eth-rpc-proxy &

# Verify the allow-list: a read is forwarded, admin_* is rejected.
curl -s -X POST http://127.0.0.1:8547 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | jq -r '.result'
curl -s -X POST http://127.0.0.1:8547 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"admin_nodeInfo","params":[]}'      # -> method not found
```

Optionally run the `faucet` (drips gas to new addresses) from a prefunded EOA;
it also submits through reth's loopback RPC and carries its own per-address /
per-IP limits. See `faucet --help` for its env config.

---

## Appendix: generate + run the validator testnet (operators)

The trusted set is generated from one command. From the repo root:

```sh
# 3 validators + 1 full node, chain-id 767676, on loopback:
crates/boule-reth/gen-testnet.sh

# Custom topology, real interface, extra prefund (e.g. a faucet EOA, #806):
N=4 M=2 CHAIN_ID=767676 HOST=10.0.0.5 \
  PREFUND="0xFaucetAddr…:1000000000000000000000 0xDevAddr…:5000000000000000000" \
  OUTDIR=/srv/testnet crates/boule-reth/gen-testnet.sh
```

This produces, in `OUTDIR`:

- `genesis/genesis.json` — seeded with the minted validators' **weights**
  (the Registry must seed weights or weighted quorum is inert), the chain-id,
  and the prefund allocations.
- `configs/node{0..K}.toml` — one per node (validators then full nodes), with
  public + admin listeners, the static seed-peer mesh, and the reth EL wiring.
- `keys/` — minted node + BLS keys (mode `0600`).
- `docker-compose.yml`, `systemd/*.service`, `run-local.sh` — run tooling
  (each node = its own reth EL + a `boule` process).

Bring it up locally with docker, or bare-process:

```sh
cd /srv/testnet && docker compose up -d        # containers
# or, bare-process (boule + boule-reth-node on PATH):
/srv/testnet/run-local.sh
```

### Prefund / faucet

Any number of `(address, balance_wei)` pairs can be prefunded at genesis via
the `PREFUND` env (or `gen-testnet-genesis --prefund <0xADDR>:<WEI>`). A faucet
account is simply one more prefund entry — the genesis builder has no coupling
to any faucet implementation.

### Chain-id

`CHAIN_ID` (default `767676`) sets the EVM `config.chainId` in `genesis.json`.
Pick a value unlikely to collide with a public network; it is independent of
the boule **consensus** chain-id, which is derived from the genesis parts
(validator set + BLS keys + seed) and binds the BLS proofs-of-possession.

### Seed peers / discovery

The generated configs use a **static full-mesh** `[[peers]]` list (every node
pins every other by `host:port` + NodeId) — appropriate for a trusted testnet.
The reth ELs additionally peer via `enode://` URLs: after first boot, read each
reth's enode (`admin_nodeInfo`) and paste it into the other nodes'
`[consensus.application] reth_peers`, or let reth discovery find them.
