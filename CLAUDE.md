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
- For a single PR with no stack: once CI is green, squash-merge with
  `gh pr merge <N> --squash --delete-branch`. Rebase first if the
  branch is behind `main`.
- For a **stack of PRs**, set each PR's base to its parent (PR2 → PR1,
  PR3 → PR2), not to `main`. When the whole stack is ready, collapse
  it into the bottom PR before landing on main:
    1. Top-down, squash-merge each child into its parent
       (`gh pr merge <child> --squash --delete-branch`). The child
       PR's content lands on the parent's branch as a single commit
       and the child PR auto-closes. GitHub auto-retargets the next-
       up PR's base to the now-deleted child's parent, so the chain
       collapses cleanly.
    2. After every intermediate squash, the bottom PR's branch
       contains the whole stack as one commit per former-child plus
       its own commits. Rebase onto current `main` if needed.
    3. Squash-merge the bottom PR to `main`. `main` gets one commit
       per stack, titled after the bottom PR.
- If pre-merge CI fails, fix on the same branch and push.
- If a merge fails on a CI flake (single test, passes on rerun, no
  recent change to that test), retry once. If it fails again on the
  same test, file an issue for the flake and stop.
- Don't merge a draft PR or one whose CI hasn't actually run.

## Issue labels

Every new issue must have exactly one `priority: <low|medium|high>` and one
`size: <small|medium|large>` label. Propose both when filing and confirm with
the user if the call isn't obvious. Do **not** add other labels (`enhancement`,
`bug`, topical labels like `research`, etc.) unless the user explicitly asks.

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
