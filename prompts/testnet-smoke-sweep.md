# Testnet smoke sweep — `boule`

Issue-agnostic smoke test of the multi-process testnet. The deterministic
orchestration now lives in a compiled, tested cargo test —
`crates/boule-cli/tests/smoke_sweep.rs` — a tier-gated scenario matrix run
against real clusters, with per-trial safety and steady-state back-pressure
checks reading typed `ConsensusStatus` counters (no log/JSON parsing).
**Your job is the judgment layer: pick the tier, run the test, then read
the report and investigate anything that failed.** Do not re-implement the
orchestration in shell — extend the test instead.

It is **not** part of the per-PR gate. The sweep is `#[ignore]`d (so the
stable gate compiles but skips it) and runs on a nightly schedule + the
`smoke` PR label via `.github/workflows/smoke.yml`, the same cadence as the
fuzz target.

## Step 1: pick a tier — STOP and ask the user first

Before running, ask which tier (sets the `SMOKE_TIER` env var):

- **`quick`** (~5 min) — Tier A core smoke: rotating-failure, kill→restart
  catch-up, disconnect-random, 7-node gossip + back-pressure, path probe, BLS.
- **`standard`** (default, ~12 min) — adds 3-seed variance sweeps and the
  footgun/gated custom-scenario pair.
- **`extended`** (~30 min) — adds the partition probe (3 seeds) and the
  10-seed sequential-kill sweep.
- **`full`** (~22 min wall, heaviest) — the full 65-trial sweep: Tier A + B +
  the 5-seed partition probe, 20-seed restart-recovery, and 20-seed
  sequential-kill sweeps.

If the user doesn't answer, default to **`standard`**.

## Step 2: run

```sh
SMOKE_TIER=<chosen> cargo test --release -p boule-cli --test smoke_sweep \
  -- --ignored --nocapture --test-threads=1
```

The `boule` node binary is located automatically via `CARGO_BIN_EXE_boule`.
The test prints live per-trial progress and a final pass/fail table to
stderr; it fails (non-zero) if any trial fails, and on each failure dumps
that cluster's verify-safety count, per-node status, and log tails *before*
teardown.

Each row is `group  seed  result  detail`:

- `group` — scenario id (`a1`, `b4a`, `d1-42`, …).
- `detail` — for passes, the key metric (`emit=15 recv=4`, `gossip_min=2`,
  `partitioned-recovered`); for fails, the reason (`back-pressure grew:
  node1:0->21`, `2 safety violation(s)`, `unpartitioned-wedge`).

## Step 3: interpret + report

- **Any `FAIL` is the headline.** The test already dumped diagnostics inline
  (status + log tails); summarize them. If you need more, re-run a single
  group with `SMOKE_TIER=quick` or by adapting the matrix locally.
- **Safety violations** (`N safety violation(s)`) are the most serious — flag
  above everything else.
- **Back-pressure growth** (`back-pressure grew: …`) means a node's
  `gossip_sink_overflow_total` climbed on a healthy cluster — a real
  back-pressure regression, not noise.
- **`unpartitioned-wedge`** means connected survivors stopped progressing — a
  genuine liveness bug. `partitioned-recovered` is an expected partial-sync
  stall that healed; treat it as a pass.
- **`b4a` footgun** is *expected* to wedge (it passes by failing). If it
  reports the cluster did **not** wedge, that's a change in engine behaviour
  worth flagging, not a bug in the test.

Write a short structured summary: one-line verdict (`all N passed`, or
`M failed across <groups>`), the tier, a row per scenario group, and the
verbatim diagnostic dump for every failure.

## Don't

- Don't re-derive the orchestration in shell — extend
  `crates/boule-cli/tests/smoke_sweep.rs`, where the matrix, thresholds, and
  checks are compiled and tested.
- Don't commit, push, open issues, or post comments — observe-only.
- Don't diagnose root causes in the verdict; capture and report what's
  observable. Pattern-matching to known signatures is fine in notes.
