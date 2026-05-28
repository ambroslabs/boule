# Contributing to ambros-p2p

Thank you for your interest in contributing!

## Contributor Representations

This project is dual-licensed under the MIT license (see
[LICENSE-MIT](LICENSE-MIT)) and the Apache License, Version 2.0 (see
[LICENSE-APACHE](LICENSE-APACHE)) at the user's option. By opening a pull
request against this repository, the GitHub account that authors the PR
represents and warrants that:

1. They are the author of the contributed code, or otherwise have the legal
   right to submit it under the terms of `MIT OR Apache-2.0`.
2. The contribution does not knowingly incorporate third-party material that
   is incompatible with `MIT OR Apache-2.0`, and any third-party material it
   does incorporate is used in compliance with its license (with attribution
   and license notices preserved as required).
3. If the contributor's employer holds rights to the work, the contributor
   has obtained the necessary permission to contribute it under
   `MIT OR Apache-2.0`.
4. The contribution is licensed to the project and its users under the terms
   of `MIT OR Apache-2.0` (inbound=outbound).

The authoring GitHub account identified on the pull request is the party
responsible for these representations. No separate sign-off or DCO trailer
is required.

## Development Setup

**Prerequisites:** Rust stable (≥ 1.85, edition 2024). The `rust-toolchain.toml`
file ensures the correct toolchain is selected automatically.

```sh
git clone https://github.com/ambroslabs/ambros-p2p.git
cd ambros-p2p
cargo build
```

## Running Tests

The integration tests spin up real nodes in subprocesses:

```sh
cargo test --test integration_test
```

Unit tests (when present):

```sh
cargo test --lib
```

### Compute-heavy tests

CI splits the test suite across two shards: a `heavy` shard that runs
CPU-bound tests one at a time, and a `default` shard that runs the rest in
parallel. This keeps cryptographic tests (BLS pairing / PoP) and large
consensus simulations from starving each other on a shared runner.

If your new test is CPU-bound *and* its isolated wall-clock is longer than a
few seconds, classify it as heavy. Two places to update — keep them in sync:

- `.config/nextest.toml` — `[[profile.default.overrides]].filter`
- `.github/workflows/ci.yml` — the `HEAVY_FILTER` env in the `test` job

The leading comment in `.config/nextest.toml` documents the convention. New
tests that match an existing pattern (for example, anything in
`crypto::bls_key::tests`) are picked up automatically.

## Code Style

Formatting and linting are enforced in CI. Before pushing, run:

```sh
cargo fmt --all          # auto-format
cargo clippy --all-targets -- -D warnings   # must produce no errors
```

The project follows standard Rust idioms. Clippy warnings are treated as
errors in CI, so resolve them rather than suppressing them unless there is a
clear documented reason.

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`.
2. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass locally.
3. Open a PR against `main` with a clear description of the change and why.

If your change touches the public API or wire format, note that in the PR
description — those changes require extra care around compatibility.

## License

All contributions are accepted under the dual terms of [LICENSE-MIT](LICENSE-MIT)
and [LICENSE-APACHE](LICENSE-APACHE) (`MIT OR Apache-2.0`). See "Contributor
Representations" above for the rights and warranties every pull request author
makes when submitting code.
