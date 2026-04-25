# CLAUDE.md

Project overview lives in [README.md](README.md); contributor terms and the
PR checklist live in [CONTRIBUTING.md](CONTRIBUTING.md). Read those first.

## Commands

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo deny check
```

CI runs `fmt`, `clippy`, `test`, and `cargo-deny`. All four must pass before a
human reviews the PR. The SessionStart hook in `.claude/hooks/session-start.sh`
installs `cargo-deny` for remote sessions; if `cargo deny` is missing locally,
install it (e.g. `cargo install --locked cargo-deny`) rather than skipping the
check.

## Workflow

- When an issue is code-complete, open a PR and monitor CI to green.
- Reference the issue in the PR body with a closing keyword (`Closes #N`,
  `Fixes #N`) so it auto-closes on merge.
- Do **not** merge. Wait for human review and let the human merge.
- If CI fails, fix it on the same branch and push again.
