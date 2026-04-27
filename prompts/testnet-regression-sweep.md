# Testnet driver regression sweep — `zrbecker/ambros-p2p`

## Goal

Smoke-test the `testnet` binary against the scenarios documented in
`docs/testnet-local.md` and a few exploratory variants. Run all ten scenario
groups so any regression — not just in the recently-touched code paths —
surfaces. Sweeps with multiple seeds are explicitly sized to catch ~5–20%
intermittent failure rates on restart-recovery scenarios. Don't go in with a
hypothesis; run the scenarios as written and report any trial that wedges,
fails safety, or behaves anomalously.

## Setup

In a clean checkout of `zrbecker/ambros-p2p` at `origin/main` HEAD, from the
repo root:

```sh
cargo build --release --bin testnet --bin ambros-p2p
mkdir -p /tmp/regression-runs
BIN=$(pwd)/target/release/ambros-p2p
TESTNET=$(pwd)/target/release/testnet
```

Conventions:

- Every trial uses a fresh workdir under `/tmp/regression-runs/`. Tear down
  with `testnet down --workdir $WD; rm -rf $WD` between trials. Never reuse
  a workdir across trials except where a scenario explicitly says to.
- Always pass `--ambros-bin $BIN` explicitly to `new`, `up`, and `scenario`
  invocations.
- After every scenario: `testnet snap`, `testnet verify-safety` (capture
  exit code), `testnet telemetry`. A non-zero `verify-safety` exit is the
  most serious kind of failure.

## Scenarios

### 1. Documented `rotating-failure-7n-f2` — sweep 5 seeds, partition-aware

The built-in `rotating-failure-7n-f2` scenario auto-tears-down on a wedge,
which destroys the gossip-mesh state we need for the partition probe. Drive
its shape manually here so the cluster stays up after the wedge.

For seed in `1 7 42 102 107`:

```sh
WD=/tmp/regression-runs/s1-$SEED
$TESTNET new --nodes 7 --seed $SEED --workdir $WD --ambros-bin $BIN
$TESTNET up --workdir $WD --ambros-bin $BIN
$TESTNET wait --all-reach-height 5 --workdir $WD --timeout 30
$TESTNET kill --random 2 --seed $SEED --workdir $WD
INITIAL_MAX=$($TESTNET snap --workdir $WD --json | \
  jq '[.[]|select(.status|startswith("up"))|.last_committed_height]|max')
TARGET=$((INITIAL_MAX + 10))
$TESTNET wait --all-reach-height $TARGET --workdir $WD --timeout 30
WAIT_EXIT=$?
$TESTNET verify-safety --workdir $WD   # exit MUST be 0 in every branch below
$TESTNET telemetry --workdir $WD
```

Branch on `WAIT_EXIT`:

**(A) `WAIT_EXIT == 0` — survivors progressed.** Pass. Tear down
(`testnet down --workdir $WD; rm -rf $WD`).

**(B) `WAIT_EXIT != 0` — survivors wedged.** Do *not* classify as a failure
yet. Run the partition probe:

1. Read `state.json` to get each surviving validator's `node_id` and
   `api_addr`.
2. For each survivor, `curl http://$api_addr/peers` → list of base58
   NodeIds.
3. Build an undirected graph on the survivor NodeId set (edge `A–B` if `B`
   appears in `A`'s peer list *or* `A` appears in `B`'s — `/peers` only
   shows direct connections; either-direction is sufficient evidence of a
   routable link).
4. Run BFS from any survivor. If every other survivor is reachable,
   `PARTITIONED=false`; otherwise `PARTITIONED=true`.
5. Read `consensus.timeout_max_ms` from `$WD/node1/config.toml`. Set
   `HALT_SECS = timeout_max_ms × 3 / 1000` (default → 30 s).

Then:

- **`PARTITIONED=false` + wedge → real bug.** The honest 5-of-7 quorum had
  full gossip-mesh connectivity, so partial-synchrony allowed (in fact
  required) consensus to make progress and it didn't. Capture: snap,
  verify-safety exit, telemetry, last 30 lines of `testnet logs <node>` for
  the lowest-height survivor, `bootstrap_peers` from `state.json`, and the
  per-survivor `/peers` dump that established connectivity. Report as a
  failure. Tear down.

- **`PARTITIONED=true` + wedge → expected partial-sync stall, now probe
  recovery.**

  ```sh
  $TESTNET wait --quiescent --for $HALT_SECS --workdir $WD --timeout $((HALT_SECS+30))
  for n in $(grep '"kind":"kill"' $WD/events.jsonl | jq -r .node); do
    $TESTNET up $n --workdir $WD --ambros-bin $BIN
  done
  $TESTNET wait --all-reach-height $((TARGET+5)) --workdir $WD --timeout 60
  RECOVER_EXIT=$?
  $TESTNET verify-safety --workdir $WD
  $TESTNET telemetry --workdir $WD
  ```

  - `RECOVER_EXIT == 0`: **pass with caveat.** The seed produced a
    graph-partitioned survivor subgraph (a bound on the gossip layer's
    cold-start robustness, not a consensus bug); the cluster recovered once
    the partition healed. Note in the report.
  - `RECOVER_EXIT != 0`: **real bug** in the recovery path. Capture full
    diagnostics as in the no-partition case.

Pass condition: `verify-safety` exit 0 in every branch, *and* either (A), or
(B) terminating in `RECOVER_EXIT == 0`.

### 2. Documented 4-node `rotating-failure --f 1` — sweep 5 seeds

Seeds `7 11 42 73 113`. Same shape as the original §1 (let
`testnet scenario` drive it; auto-teardown is fine here because we don't
need post-wedge state):

```sh
WD=/tmp/regression-runs/s2-$SEED
$TESTNET new --nodes 4 --seed $SEED --workdir $WD --ambros-bin $BIN
$TESTNET scenario rotating-failure --f 1 --seed $SEED --workdir $WD --ambros-bin $BIN
$TESTNET snap --workdir $WD
sleep 5
$TESTNET snap --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

Pass condition: scenario completes; second snap shows higher
`last_committed_height` on surviving nodes; `verify-safety` exit 0.

### 3. Manual kill → restart → catch-up — 3 trials, fresh workdir each

```sh
WD=/tmp/regression-runs/s3-$TRIAL
$TESTNET new --nodes 4 --seed 42 --workdir $WD --ambros-bin $BIN
$TESTNET up   --workdir $WD --ambros-bin $BIN
$TESTNET wait --all-reach-height 5  --workdir $WD
$TESTNET kill node2                 --workdir $WD
$TESTNET wait --all-reach-height 15 --workdir $WD --timeout 30
$TESTNET up   node2                 --workdir $WD --ambros-bin $BIN
$TESTNET wait --node node2 --catch-up-to-cluster --tolerance 2 --workdir $WD --timeout 60
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

Pass condition: every `wait` returns exit 0; post-catch-up `telemetry` shows
`block_sync_request_emitted > 0` on `node2` and
`block_sync_request_received > 0` on the survivors.

### 4. Built-in `scenario reconnect <node>` — 1 trial

Reuse the workdir from the *first* trial of #3 (re-create with
`testnet new` if you didn't keep it). Then:

```sh
$TESTNET kill node2 --workdir $WD
$TESTNET scenario reconnect node2 --workdir $WD --ambros-bin $BIN
$TESTNET snap --workdir $WD; sleep 7; $TESTNET snap --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

Pass condition: scenario steps all `ok`; second snap shows progress;
`verify-safety` exit 0. Note: a benign-looking step report
`up=node2 (already running)` is expected (the scenario CLI auto-spawns the
cluster before running explicit `up` steps); not a failure.

### 5. Built-in `scenario disconnect-random` — sweep 5 seeds × 7 nodes

For seed in `1 7 42 102 107`:

```sh
WD=/tmp/regression-runs/s5-$SEED
$TESTNET new --nodes 7 --seed $SEED --workdir $WD --ambros-bin $BIN
$TESTNET scenario disconnect-random --count 2 --liveness-window 5 --seed $SEED --workdir $WD --ambros-bin $BIN
$TESTNET snap --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

The flag is `--liveness-window`, not `--restart-after`. (The latter is a
deprecated alias and emits a warning.)

### 6. Gossip end-to-end — 1 trial

```sh
WD=/tmp/regression-runs/s6
$TESTNET new --nodes 7 --seed 1 --workdir $WD --ambros-bin $BIN
$TESTNET up --workdir $WD --ambros-bin $BIN
$TESTNET wait --all-healthy --within 5 --workdir $WD --timeout 30
# Look up each node's api_addr in $WD/state.json
EXPIRY=$(date -u -d '+2 minutes' +%Y-%m-%dT%H:%M:%SZ)
curl -s -X POST http://127.0.0.1:<api1>/messages \
     -H 'content-type: application/json' \
     -d "{\"content\":\"hello-cluster\",\"expiry\":\"$EXPIRY\"}"
sleep 2
# GET /messages on every other node — all must return the same content
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

Pass condition: every node serves the message at GET;
`gossip_send_to_dispatched > 0` on every node in the post-trial telemetry.

### 7. Custom `warmup-then-disconnect` TOML — 2 trials

**Trial 7a (footgun pattern, expected to fail):** Author this scenario file
and run against `--seed 7`:

```toml
[scenario]
seed = 7
name = "warmup-then-disconnect-no-mesh-gate"

[[steps]]
op = "wait_all_reach_height"
height = 30

[[steps]]
op = "kill_random"
count = 2

[[steps]]
op = "wait_all_reach_height"
height = 60
timeout_secs = 60

[[steps]]
op = "verify_safety"
```

```sh
$TESTNET new --nodes 7 --seed 7 --workdir $WD --ambros-bin $BIN
$TESTNET scenario --file /path/to/scenario.toml --workdir $WD --ambros-bin $BIN
echo "exit=$?"
```

This scenario is documented (`docs/testnet-local.md` §7 commentary) as
failing with seed=7+count=2 because the kill set isolates a node before
gossip mesh expansion. The expected outcome is a non-zero exit and a
stalled cluster — that's an *engine-level footgun*, not a regression. Note
in the report whether the failure mode matches expectation
(`wait_all_reach_height(60)` step times out).

**Trial 7b (fixed pattern, expected to pass):** Same scenario but with a
`wait_all_healthy` step inserted as the first step:

```toml
[[steps]]
op = "wait_all_healthy"
within = 5
```

Run against `--seed 7`. Expected: scenario completes successfully,
`verify-safety` exit 0.

### 8. Restart-from-divergent-disk-state — sweep 20 seeds

This sweep is sized to catch any intermittent post-restart liveness failure
at ≥5% rate. **One of the most important sweeps in this run.**

For seed in `1 7 11 13 17 23 29 42 50 64 73 89 97 100 102 107 113 127 131 149`:

```sh
WD=/tmp/regression-runs/s8-$SEED
$TESTNET new --nodes 4 --seed $SEED --workdir $WD --ambros-bin $BIN
$TESTNET scenario rotating-failure --f 1 --seed $SEED --workdir $WD --ambros-bin $BIN
$TESTNET snap --workdir $WD
$TESTNET down --workdir $WD
$TESTNET up   --workdir $WD --ambros-bin $BIN
$TESTNET wait --all-reach-height 50 --workdir $WD --timeout 30
echo "trial $SEED wait_exit=$?"
$TESTNET snap --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

Pass condition: `wait` exit 0; `verify-safety` exit 0. A `wait` timeout *or*
heights frozen post-up *or* `block_sync_request_emitted=0` everywhere on
the lagging replica is a failure to investigate.

### 9. Workdir path probes — 2 trials

**9a (relative workdir on `new`, absolute path from a different cwd):**

```sh
cd /tmp/regression-runs && $TESTNET new --nodes 4 --workdir s9-rel --ambros-bin $BIN
cd / && $TESTNET up --workdir /tmp/regression-runs/s9-rel --ambros-bin $BIN
$TESTNET wait --all-reach-height 5 --workdir /tmp/regression-runs/s9-rel --timeout 30
$TESTNET down --workdir /tmp/regression-runs/s9-rel; rm -rf /tmp/regression-runs/s9-rel
```

**9b (absolute workdir on `new`, all subsequent commands from `/`):**

```sh
cd / && $TESTNET new --nodes 4 --workdir /tmp/regression-runs/s9-abs --ambros-bin $BIN
$TESTNET up --workdir /tmp/regression-runs/s9-abs --ambros-bin $BIN
$TESTNET wait --all-reach-height 5 --workdir /tmp/regression-runs/s9-abs --timeout 30
$TESTNET down --workdir /tmp/regression-runs/s9-abs; rm -rf /tmp/regression-runs/s9-abs
```

Pass condition: every command succeeds.

### 10. 3-of-4 sequential-kill restart wedge — sweep 20 seeds

This sweep regresses
[#222](https://github.com/zrbecker/ambros-p2p/issues/222) — a post-restart
liveness wedge where the first-killed replica freezes at its persisted
`(last_voted_view, last_committed_height)` while the rest of the cluster
advances normally. `verify-safety` is clean every time; this is liveness,
not safety. Discovered at ~12% rate; sized to catch ≥5% intermittent rate.
Follow-up to the WIP fix in #218.

For seed in `1 7 11 13 17 23 29 42 50 64 73 89 97 100 102 107 113 127 131 149`:

```sh
WD=/tmp/regression-runs/s10-$SEED
$TESTNET new --nodes 4 --seed $SEED --workdir $WD --ambros-bin $BIN \
  --timeout-base-ms 200 --timeout-max-ms 2000
$TESTNET up --workdir $WD --ambros-bin $BIN
$TESTNET wait --all-reach-height 5 --workdir $WD --timeout 30
PRE_H=$($TESTNET snap --workdir $WD --json | \
  jq '[.[]|select(.status|startswith("up"))|.last_committed_height]|max')
$TESTNET kill node2 --workdir $WD
$TESTNET kill node3 --workdir $WD
$TESTNET kill node4 --workdir $WD
sleep 30
$TESTNET up node2 --workdir $WD --ambros-bin $BIN
$TESTNET up node3 --workdir $WD --ambros-bin $BIN
$TESTNET up node4 --workdir $WD --ambros-bin $BIN
$TESTNET wait --all-reach-height $((PRE_H+10)) --workdir $WD --timeout 60
WAIT_EXIT=$?
$TESTNET snap --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD
[ $WAIT_EXIT -eq 0 ] && rm -rf $WD     # preserve workdir on failure
```

Pass condition: `wait` exit 0 AND `verify-safety` exit 0.

The wedge signature (when present): one node — almost always `node2`, since
it's killed first and has the lowest persisted view — sits at
`view ≈ persisted last_voted_view`, `height ≈ persisted last_committed_height`,
while the other 3 nodes have advanced ≥10 heights. `peers=3` on the wedged
node (mesh formed). Telemetry on the wedged node shows
`block_sync_request_emitted=0` and `proposal_rejected_unknown_parent=0` —
the smoking-gun signature.

For a failure: capture snap, `verify-safety` exit, telemetry, last 30 lines
of `testnet logs <wedged>` (almost always `node2`), and `state.json`'s
`bootstrap_peers`. **A failure here is a known intermittent bug (#222 /
follow-up to #218 WIP) — note in the report whether the signature matches.**
Drift in signature (e.g. wedged node ≠ first-killed, `view` ≠ persisted
`last_voted_view`, or `block_sync_request_emitted > 0` on the wedged node)
would mean a *new* bug and should be flagged separately.

## What to report

A structured summary with one section per scenario group:

| Scenario | Trials run | Passes | Failures | Notes |

For S1 specifically, additionally classify each trial's branch:

| Seed | Branch | Outcome |
| --- | --- | --- |
| 1 | `healthy` / `partitioned-recovered` / `partitioned-not-recovered` / `unpartitioned-wedge` | pass / fail |

Aggregate verdict treats `healthy` and `partitioned-recovered` as passes;
`partitioned-not-recovered` and `unpartitioned-wedge` are failures.

For every failure (across any scenario):

- Scenario name, seed (if applicable), the exact step / command that
  failed, exit code.
- Post-failure `testnet snap` output verbatim.
- Post-failure `testnet verify-safety` exit code.
- Post-failure `testnet telemetry` output verbatim.
- Last 30 lines of `testnet logs <node>` for the most-stuck node (lowest
  height).
- `bootstrap_peers` from `state.json` if relevant.
- For S1 `unpartitioned-wedge` failures: the per-survivor `/peers` dump
  that established the survivor subgraph was connected.
- For S10 failures: whether the signature matches the documented #222
  pattern (first-killed node stuck at persisted `last_voted_view`, others
  caught up, `block_sync_request_emitted=0` on the wedged node) or drifts
  from it.

A one-line aggregate verdict at the top: **all pass** or **N trials failed
across <which sweeps>**.

Flag explicitly whether scenario 7a's failure mode matched expectation;
that's documented behaviour, not a bug. Likewise, classify S10 failures as
matching/drifting from the #222 signature.

## Don't

- Don't commit, push, open issues, or post comments. Observe-only.
- Don't reduce the seed counts (especially in scenarios 8 and 10) to save
  time. The 20-seed sweeps are sized intentionally — at 5% failure rate, 20
  trials yields ~1 expected failure; at 20% rate, ~4. A smaller sample
  would bury intermittent bugs.
- For S10, don't classify "all 20 seeds passed" as a fix verification
  unless the run was on a build that's supposed to fix #222. On builds
  where #222 is known-unfixed, the expected outcome is 1–4 wedges; zero
  wedges means scheduler luck, not absence of bug.
- Don't skip `verify-safety` even on apparent passes. A silent safety
  violation matters more than a wedge.
- Don't try to diagnose root causes. Just capture and report what's
  observable.

## Time budget

≤ 90 minutes total. Build is ~3–4 min from cold; each failed `wait` burns
30–60 s of dead time. Each S10 trial is fixed ~95 s (5 s warmup + 30 s
delay + 60 s recovery budget); the 20-seed S10 sweep adds ~32 minutes on
its own. Run sweeps in series unless your harness handles concurrent
testnet workdirs cleanly (the per-node ports are auto-allocated so
concurrent runs are technically safe but consume more memory).

Report in under 800 words plus the verbatim failure dumps.
