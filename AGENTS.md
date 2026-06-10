# AGENTS.md

Rust P2P consensus node.

- Read [README.md](README.md)
- Read [CONTRIBUTING.md](CONTRIBUTING.md)
- Before Pushing to PR
    - `cargo fmt --all`
    - `cargo clippy --all-targets -- -D warnings`
    - `cargo test --locked`
    - `cargo deny check`
- Never commit compiled bytecode or other build artifacts, generate them from source at build time.
- Close issues from the PR body: `Closes #N` / `Fixes #N`.
- New issues need exactly one `priority:` and one `size:` label: no other labels unless asked.
