# boule

[![CI](https://github.com/ambroslabs/boule/actions/workflows/ci.yml/badge.svg)](https://github.com/ambroslabs/boule/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **boule** — from the ancient Greek *βουλή* (boulē, /buːˈleɪ/, "boo-LAY"),
> the citizen council of classical Athens that deliberated to reach
> collective decisions. A fitting namesake for a Byzantine-fault-tolerant
> consensus system.

A peer-to-peer runtime written in Rust, hosting a HotStuff-style BFT
consensus layer. Every subsystem below consensus — TLS transport, gossip,
signed envelopes, clock, durable storage — lives behind an object-safe
seam so the whole stack can be driven by a deterministic in-process
simulator during tests.

## Quickstart

Prerequisites: Rust stable (≥ 1.85, edition 2024). The `rust-toolchain.toml`
in the repo root pins the toolchain; `rustup` will pick it up automatically.

```sh
# Build
cargo build

# Bootstrap a single node (writes a starter config at the platform
# default location if --config is omitted)
cargo run --bin boule -- init --config config.toml

# Run that node
cargo run --bin boule -- start --config config.toml

# Unit tests (includes the deterministic simulator)
cargo test --lib

# Integration tests (spawn real nodes in subprocesses; TLS + gossip end-to-end)
cargo test --test integration_test

# Rendered API docs, including the crate-level overview
cargo doc --document-private-items --open

# Doctests (any code in `//!` / `///` blocks)
cargo test --doc

# HotStuff safety-core property tests at higher seed counts. The
# default (256 cases) runs in about a second; deeper runs catch
# rarer Byzantine interleavings. A failing case is saved to
# `proptest-regressions/` so the exact seed persists across runs.
PROPTEST_CASES=4096 cargo test -p boule-consensus --lib hotstuff::step::tests::property
```

Format and lint before pushing:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

## Workspace layout

`boule` is a Cargo workspace. `boule-core` is the leaf every other crate
builds on; `boule-consensus` and `boule-transport-tcp` sit on top of it as
siblings; `boule-node` wires them into a runtime; `boule-cli` is the
binary.

| Crate                 | Role                                                                                                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `boule-core`          | Leaf primitives shared by everything: config, Ed25519/BLS signing and `Signed<T>` envelopes, the object-safe `Clock`, `Storage`/`Wal` KV traits, node identity, and transport rate-limit policy. |
| `boule-consensus`     | HotStuff-style BFT: the safety core, pacemaker, message dispatch + wire format, block/mempool/snapshot replication and the state-machine seam, and validator-set rotation. |
| `boule-transport-tcp` | TLS-authenticated transport, peer manager, dialer, RPC, and the gossip overlay (`Broadcaster` + `Discovery`). A node's Ed25519 public key is its overlay address.    |
| `boule-node`          | The runtime that drives consensus over the transport, plus the `#[cfg(test)]` deterministic simulator and the local testnet driver.                                  |
| `boule-cli`           | The `boule` binary, its subcommands, and the end-to-end integration tests.                                                                                           |

Each crate's `lib.rs` carries its own module breakdown; `cargo doc` is the
authoritative reference.

## Configuration

A minimal `config.toml`:

```toml
[node]
listen_addr = "0.0.0.0:7000"

[api]
# Public, read-only HTTP surface: GET /consensus/status, /peers, /metrics,
# /health, /ready. Safe to expose to a load balancer / monitoring stack.
listen_addr = "127.0.0.1:8080"

# Privileged operator surface (POST /admin/rotate-key, /mempool/submit),
# isolated onto its own listener. Off by default — set listen_addr to a
# trusted interface (loopback / private subnet) to enable it. Optionally
# require a bearer token as a second layer.
# [api.admin]
# listen_addr    = "127.0.0.1:8090"
# auth_token_env = "BOULE_ADMIN_TOKEN"   # request must send: Authorization: Bearer <token>

# [[peers]]
# addr = "127.0.0.1:7001"
```

The public listener never serves the privileged routes. Operators wire
`/health` (liveness) and `/ready` (readiness: committed progress + a
healthy view, and — for validators — at least one peer) into their load
balancer, and scrape `/metrics` (Prometheus text) for consensus + p2p
health.

The node's long-term Ed25519 identity can be sourced from a file, an
environment variable, an encrypted file, an OS keyring, or an external
command; see the `[node.identity]` table and the `key migrate` subcommand
(`cargo run --bin boule -- --help`).

When `--config` is omitted, `boule` reads from the platform-specific
default (`$XDG_CONFIG_HOME/boule/config.toml` on Linux, the standard
Library directory on macOS, `%APPDATA%\boule\config.toml` on
Windows). Run `boule init` to write a starter template at that path
on first use.

### Topology overlay (gossip)

Consensus consumes a `Broadcaster` + `Discovery` pair
(`crates/boule-transport-tcp/src/overlay/`) so the underlying topology
is a black box. The production overlay is **`gossip`**: each node keeps a
bounded set of direct TLS connections (up to `outbound_target` it dials
out, `inbound_max` it accepts, `total_max` overall) and learns about the
rest of the validator set through periodic peer-list gossip. Add new
operators by pointing one or two seed addresses at any reachable
validator; no coordinated config rollouts when the validator set grows.

Tune it with the `[overlay]` table:

```toml
[overlay]
outbound_target = 8             # direct peers this node dials out to
inbound_max = 16                # direct peers it accepts inbound
total_max = 24                  # hard ceiling on direct peers
peer_gossip_interval_ms = 5000  # peer-list publish cadence
mesh_check_interval_ms = 5000   # partial-mesh maintenance dial cadence
bootstrap_addrs = ["10.0.0.1:7000"]  # TOFU seeds
```

The remaining knobs (`peer_gossip_fanout`, `dedup_capacity`,
`dedup_ttl_ms`, `peer_table_capacity`) tune the gossip overlay's
internals; defaults are sized for validator-set-scale clusters and
most operators leave them alone. See `OverlayConfig` in
[`crates/boule-core/src/config.rs`](crates/boule-core/src/config.rs)
for the full schema.

`bootstrap_addrs` are TOFU dials — the gossip overlay accepts whatever
TLS identity the peer presents on first contact and updates its
peer-table entry from the peer's own self-advertised
`(node_id, listen_addr)` on the next gossip tick. `[[peers]]` and
`bootstrap_addrs` compose: anything in `[[peers]]` is dialed at boot
with a verified `node_id`, and anything in `bootstrap_addrs` is
dialed lazily in TOFU mode.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor representations,
development setup, and PR checklist.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual-licensed as above, without any additional terms or conditions.
