# AGENTS.md

Rust P2P consensus node. Read [README.md](README.md) (what it is) and
[CONTRIBUTING.md](CONTRIBUTING.md) (setup, test shards, PR flow) first.

## Module map (`src/`)

Layered top-to-bottom; `src/lib.rs` has the full layer diagram.

- `consensus/` — HotStuff-style BFT replica: safety core, `pacemaker/`, `hotstuff/`, validator set + rotation, block/snapshot sync.
- `replication/` — block, mempool, and snapshot replication plus the state machine.
- `p2p/` — TLS transport, peer `manager`, `rpc` request/response, `overlay/` (gossip), `identity/` (Ed25519 key = node address).
- `crypto/` — signing schemes (Ed25519, BLS) and `Signed` envelopes.
- `storage/` — `Storage` (KV) + `Wal` traits; in-memory (sim) and `redb` (durable) backends.
- `clock/` — object-safe time: real `TokioClock`, virtual `SimClock` for tests.
- `node.rs` — top-level runtime that wires it all together (`node::run`).
- `cli.rs`, `config.rs`, `paths.rs` — CLI subcommands, config parsing, default file locations.
- `testnet/` — local multi-node testnet driver (the `testnet` bin).

Binaries: `src/main.rs` (the `boule` node), `src/bin/testnet.rs` (testnet driver).

## Before pushing — all four gate CI

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo deny check
```

## Tests

- Hard ceiling: **≤ 15s wall per test** on a default GitHub runner. Time new tests with `--test-threads=1`.
- Prefer poll-with-budget (early-exit once the assertion holds) over fixed yield/sleep counts.
- CPU-bound and slow → mark it heavy (see CONTRIBUTING.md "Compute-heavy tests").

## PRs & issues

- Close the issue from the PR body: `Closes #N` / `Fixes #N`.
- New issues need exactly one `priority:` and one `size:` label — no other labels unless asked.
