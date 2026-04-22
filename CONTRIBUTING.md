# Contributing to ambros-p2p

Thank you for your interest in contributing!

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin v1.1](DCO) to certify
that contributors have the right to submit their work under the project license.

**Every commit must include a `Signed-off-by` trailer** with your real name and
email address:

```
Signed-off-by: Jane Smith <jane@example.com>
```

Add it automatically with the `-s` flag:

```sh
git commit -s -m "your commit message"
```

By adding the sign-off you certify the statements in the `DCO` file. If your
employer owns the copyright to your work, ensure you have permission to
contribute before signing off.

Pull requests containing unsigned commits will not be merged.

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
2. Make your changes with signed-off commits (`git commit -s`).
3. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass locally.
4. Open a PR against `main` with a clear description of the change and why.

If your change touches the public API or wire format, note that in the PR
description — those changes require extra care around compatibility.

## License

By contributing you agree that your work will be licensed under the terms in
[LICENSE](LICENSE) (GPL-3.0-only).
