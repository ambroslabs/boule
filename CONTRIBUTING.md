# Contributing to ambros-p2p

Thank you for your interest in contributing!

## Contributor Representations

This project is licensed under the GNU General Public License v3.0 (see
[LICENSE](LICENSE)). By opening a pull request against this repository, the
GitHub account that authors the PR represents and warrants that:

1. They are the author of the contributed code, or otherwise have the legal
   right to submit it under the terms of GPL-3.0-only.
2. The contribution does not knowingly incorporate third-party material that
   is incompatible with GPL-3.0-only, and any third-party material it does
   incorporate is used in compliance with its license (with attribution and
   license notices preserved as required).
3. If the contributor's employer holds rights to the work, the contributor
   has obtained the necessary permission to contribute it under GPL-3.0-only.
4. The contribution is licensed to the project and its users under the terms
   of GPL-3.0-only (inbound=outbound).

The authoring GitHub account identified on the pull request is the party
responsible for these representations. No separate sign-off or DCO trailer
is required.

## Development Setup

**Prerequisites:** Rust stable (≥ 1.85, edition 2024). The `rust-toolchain.toml`
file ensures the correct toolchain is selected automatically.

```sh
git clone https://github.com/zrbecker/ambros-p2p.git
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

All contributions are accepted under the terms of [LICENSE](LICENSE)
(GPL-3.0-only). See "Contributor Representations" above for the rights and
warranties every pull request author makes when submitting code.
