# AGENTS.md

Rust P2P consensus node. Read [README.md](README.md) (what it is) and
[CONTRIBUTING.md](CONTRIBUTING.md) (setup, test shards, PR flow) first.

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
- Land a single PR with `gh pr merge <N> --squash --delete-branch`; rebase first if behind `main`.
- New issues need exactly one `priority:` and one `size:` label — no other labels unless asked.
