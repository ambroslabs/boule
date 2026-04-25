# CLAUDE.md

Project overview lives in [README.md](README.md); contributor terms and the
PR checklist live in [CONTRIBUTING.md](CONTRIBUTING.md). Read those first.

## Commands

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

CI runs `fmt`, `clippy`, `test`, and `cargo-deny`. All four must pass before a
human reviews the PR.

## Workflow

- When an issue is code-complete, open a PR and monitor CI to green.
- Reference the issue in the PR body with a closing keyword (`Closes #N`,
  `Fixes #N`) so it auto-closes on merge.
- Do **not** merge. Wait for human review and let the human merge.
- If CI fails, fix it on the same branch and push again.

## Test performance

No single test may exceed **15 seconds** of wall-clock on a default
GitHub-hosted runner. Slow tests are usually over-budgeted yield/sleep
loops or real-time waits that consensus already finishes well before.

Prefer poll-with-budget patterns (early-exit on the same observable the
test asserts on) over fixed yield counts. For simulator tests, paused
`tokio::time` plus `tokio::task::yield_now()` is virtually free — the
real cost per yield is consensus work across the cluster, so the goal
is to stop yielding as soon as the assertion is satisfiable. When you
add a new test, time it with `--test-threads=1` before opening the PR.
