# ambros-p2p

A peer-to-peer runtime written in Rust, built as the foundation for a
HotStuff-style BFT consensus layer. Every subsystem below consensus — TLS
transport, gossip, signed envelopes, clock, durable storage — lives behind
an object-safe seam so the consensus state machine can slot in without
rewriting the plumbing, and so the whole stack can be driven by a
deterministic in-process simulator during tests.

Consensus itself is not yet implemented; the roadmap is tracked in issues
[#21–#24](https://github.com/zrbecker/ambros-p2p/issues).

## Quickstart

Prerequisites: Rust stable (≥ 1.85, edition 2024). The `rust-toolchain.toml`
in the repo root pins the toolchain; `rustup` will pick it up automatically.

```sh
# Build
cargo build

# Run a single node using the checked-in config
cargo run -- --config config.toml

# Unit tests (includes the deterministic simulator)
cargo test --lib

# Integration tests (spawn real nodes in subprocesses; TLS + gossip end-to-end)
cargo test --test integration_test

# Rendered API docs, including the crate-level overview
cargo doc --document-private-items --open

# Doctests (any code in `//!` / `///` blocks)
cargo test --doc
```

Format and lint before pushing:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

## Layer map

```text
             ┌────────────────────────────────────┐
             │             consensus              │   (future; see #21–#24)
             └─────────────────┬──────────────────┘
   signed envelopes            │            durable state
              ┌────────────────┴────────────────┐
              ▼                                 ▼
   ┌────────────────────┐              ┌────────────────────┐
   │       crypto       │              │      storage       │
   │  Ed25519 signing   │              │ Storage + Wal KV   │
   └────────────────────┘              └────────────────────┘
              │                                 │
              │           dissemination         │
              │         ┌────────────────┐      │
              └────────▶│     gossip     │◀─────┘
                        │ store + engine │
                        └───────┬────────┘
                                │ ProtocolHandle
                                ▼
                       ┌────────────────┐
                       │      p2p       │
                       │ TLS transport, │
                       │ rpc, manager   │
                       └───────┬────────┘
                               │ Clock + network I/O
                ┌──────────────┴──────────────┐
                ▼                             ▼
        ┌───────────────┐             ┌───────────────┐
        │     clock     │             │      sim      │
        │ real/virtual  │             │ deterministic │
        │     time      │             │ test harness  │
        └───────────────┘             └───────────────┘
```

Module crib sheet (see `cargo doc` for the authoritative version):

| Module    | Role                                                                              |
| --------- | --------------------------------------------------------------------------------- |
| `p2p`     | TLS-authenticated transport, peer manager, protocol multiplexer, and the RPC layer. The node's Ed25519 public key is its overlay address. |
| `gossip`  | Best-effort dissemination of opaque application messages over a `ProtocolHandle`. |
| `crypto`  | Application-level `Signed<T>` envelopes for consensus votes, proposals, etc.      |
| `clock`   | Object-safe time abstraction; `TokioClock` in prod, `SimClock` in tests.          |
| `sim`     | `#[cfg(test)]`-only deterministic simulator: in-memory pipes, virtual time, seeded RNG. |
| `storage` | `Storage` (KV) and `Wal` (append-only) traits with in-memory and `redb` backends. |
| `config`  | TOML config loading and identity-backend resolution.                              |

## Configuration

A minimal `config.toml`:

```toml
[node]
listen_addr = "0.0.0.0:7000"

[api]
listen_addr = "127.0.0.1:8080"
cleanup_interval_secs = 60

# [[peers]]
# addr = "127.0.0.1:7001"
```

The node's long-term Ed25519 identity can be sourced from a file, an
environment variable, an encrypted file, an OS keyring, or an external
command; see the `[node.identity]` table and the `key migrate` subcommand
(`cargo run -- --help`).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor representations,
development setup, and PR checklist.

## License

Licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).
