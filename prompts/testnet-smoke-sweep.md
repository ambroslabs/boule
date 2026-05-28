# Testnet smoke sweep — `ambroslabs/ambros-p2p`

## Goal

Issue-agnostic smoke test of the `testnet` binary against the scenarios in
`docs/testnet-local.md` and a few exploratory variants. Run the scenarios as
written and report any trial that wedges, fails safety, or behaves
anomalously. Don't go in with a hypothesis. The point is *what, if anything,
is going wrong* — not regression-testing any particular bug.

## Step 1: pick a time budget — STOP and ask the user first

Before running anything (including the build), ask the user which budget to
use:

- **15 min** — quick gut check. Build + core smoke. Catches obvious
  breakage in consensus, restart, gossip, and the CLI surface. No seed
  sweeps.
- **30 min** — standard. Core smoke + small (3-seed) sweeps for variance +
  custom TOML scenarios.
- **60 min** — extended. Adds a partition-aware 7-node probe and a
  10-seed restart-recovery sweep. Reasonable coverage for intermittents
  ≥10%.
- **90 min** — full. Heavy 20-seed restart-recovery sweeps sized to catch
  ≥5% intermittent failure rates.

Each tier extends the previous one. Wait for the user's selection before
starting any work. If the user doesn't answer, default to **30 min**.

## Setup (all tiers)

In a clean checkout of `ambroslabs/ambros-p2p` at `origin/main` HEAD, from the
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
- After every scenario, also run the **back-pressure check** below. Any
  per-node `backpressure.*` counter that is *non-zero and growing* is a
  failure to flag. (See `docs/backpressure.md`; the policy is that
  steady-state runs report zero, and a non-zero value means a
  documented drop class fired — usually a wedged peer or undersized
  queue.)

### Back-pressure check (every scenario, all tiers)

For each surviving node `node*`:

```sh
PORT=$(jq -r ".\"$NODE\".api_addr" $WD/state.json | cut -d: -f2)
curl -s http://127.0.0.1:$PORT/consensus/status \
  | jq '{node: "'$NODE'", backpressure}'
```

Pass: every node reports `gossip_sink_overflow_total: 0` (and any future
counters added under `.backpressure.*` stay at zero). A small one-shot
non-zero on a node that just rejoined a partition is acceptable as long
as it stops growing within ~5 s; capture both samples in the report.

Fail: a counter that *increases* across two consecutive snapshots taken
~5 s apart on a cluster that's otherwise healthy (committing, no
partition, all peers reachable). Surface this in the report alongside
the trial's `verify-safety` and telemetry output.

Build cost is ~3–4 min cold and roughly free if the release artifacts
already exist for the current HEAD.

---

## Tier A: core smoke (always — 15+)

Total wall time ~6–10 min after the build.

### A1. 4-node `rotating-failure --f 1` — 1 seed

```sh
WD=/tmp/regression-runs/a1
$TESTNET new --nodes 4 --seed 42 --workdir $WD --ambros-bin $BIN
$TESTNET scenario rotating-failure --f 1 --seed 42 --workdir $WD --ambros-bin $BIN
$TESTNET snap --workdir $WD
sleep 5
$TESTNET snap --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

Pass: scenario completes; second snap shows higher `last_committed_height`
on surviving nodes; `verify-safety` exit 0.

### A2. Manual kill → restart → catch-up — 1 trial

```sh
WD=/tmp/regression-runs/a2
$TESTNET new --nodes 4 --seed 42 --workdir $WD --ambros-bin $BIN
$TESTNET up   --workdir $WD --ambros-bin $BIN
$TESTNET wait --all-reach-height 5  --workdir $WD
$TESTNET kill node2                 --workdir $WD
$TESTNET wait --all-reach-height 15 --workdir $WD --timeout 30
$TESTNET up   node2                 --workdir $WD --ambros-bin $BIN
$TESTNET wait --node node2 --catch-up-to-cluster --tolerance 2 --workdir $WD --timeout 60
$TESTNET telemetry --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

Pass: every `wait` returns exit 0; post-catch-up telemetry shows
`block_sync_request_emitted > 0` on `node2` and
`block_sync_request_received > 0` on the survivors; `verify-safety` exit 0.

### A3. `disconnect-random` — 1 seed × 7 nodes

```sh
WD=/tmp/regression-runs/a3
$TESTNET new --nodes 7 --seed 42 --workdir $WD --ambros-bin $BIN
$TESTNET scenario disconnect-random --count 2 --liveness-window 5 --seed 42 --workdir $WD --ambros-bin $BIN
$TESTNET snap --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

The flag is `--liveness-window`, not `--restart-after` (which is a
deprecated alias).

### A4. Gossip end-to-end — 1 trial

```sh
WD=/tmp/regression-runs/a4
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

Pass: every node serves the message at GET; `gossip_send_to_dispatched > 0`
on every node in the post-trial telemetry.

### A5. Workdir path probe — 1 trial

```sh
cd /tmp/regression-runs && $TESTNET new --nodes 4 --workdir a5 --ambros-bin $BIN
cd / && $TESTNET up --workdir /tmp/regression-runs/a5 --ambros-bin $BIN
$TESTNET wait --all-reach-height 5 --workdir /tmp/regression-runs/a5 --timeout 30
$TESTNET down --workdir /tmp/regression-runs/a5; rm -rf /tmp/regression-runs/a5
```

Pass: every command succeeds (catches relative-path / cwd-coupling
regressions in the CLI).

### A6. 4-node BLS chain happy path — 1 trial

End-to-end smoke for the `bls_aggregated` signature scheme: every QC
on the wire is a real BLS aggregate, partials are signed by each
validator's BLS key, and the dispatch verifier accepts the aggregate
under the per-historical-view BLS pubkey table seeded from genesis.
Catches operator-side regressions in the BLS startup flow that the
unit + sim tests can't see (production `with_bls_signer` wiring,
`[node.bls_validator_identity]` config parse, on-disk PoP write, etc.).

```sh
WD=/tmp/regression-runs/a6
$TESTNET new --nodes 4 --seed 42 --workdir $WD --ambros-bin $BIN \
  --signature-scheme bls_aggregated
$TESTNET up   --workdir $WD --ambros-bin $BIN
$TESTNET wait --all-reach-height 5 --workdir $WD --timeout 30
$TESTNET snap --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD; rm -rf $WD
```

Pass: `wait` exit 0 (every node committed height ≥ 5 within 30 s);
`verify-safety` exit 0; per-node `bls.key` files exist under
`$WD/node{1..4}/bls.key`; the per-node `config.toml` carries
`signature_scheme = "bls_aggregated"`, a 4-row
`[[consensus.validators_bls]]` table, and a
`[node.bls_validator_identity]` block.

A startup-time refusal (e.g. `consensus.validators_bls is required`,
`BLS PoP for validator … failed to verify`, `loaded BLS pubkey … does
not match the genesis BLS pubkey`) means the BLS reconciliation in
`reconcile_bls_identity` ([src/node.rs](src/node.rs)) caught a config
inconsistency — capture the stderr in the failure dump.

**If the budget is 15 min, stop here and write the report.**

---

## Tier B: variance + custom scenarios (30+)

Adds ~12–15 min on top of Tier A.

### B1. 4-node `rotating-failure --f 1` — 3 seeds

Repeat A1 for seeds `7 42 113`, fresh workdir each
(`/tmp/regression-runs/b1-$SEED`).

### B2. Manual kill → restart → catch-up — 3 trials

Repeat A2 with seeds `1 42 107`, fresh workdir each.

### B3. `disconnect-random` 7-node — 3 seeds

Repeat A3 with seeds `1 42 102`, fresh workdir each.

### B4. Custom `warmup-then-disconnect` TOML — 2 trials

**B4a (footgun pattern, expected to fail):**

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

This is documented (`docs/testnet-local.md` §7) as failing with
seed=7+count=2 because the kill set isolates a node before gossip mesh
expansion. Expected outcome: non-zero exit, `wait_all_reach_height(60)`
times out. That's documented engine behaviour — note in the report
whether the failure mode matches expectation; flag any *change* in the
failure mode (passes when it shouldn't, or fails differently) as a
regression.

**B4b (fixed pattern, expected to pass):** Same TOML with
`wait_all_healthy { within = 5 }` inserted as the first step. Run
against `--seed 7`. Expected: scenario completes successfully,
`verify-safety` exit 0.

### B5. Restart-from-divergent-disk-state — 5 seeds

For seed in `1 42 73 100 149`:

```sh
WD=/tmp/regression-runs/b5-$SEED
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

Pass: `wait` exit 0 *and* `verify-safety` exit 0 on every seed. A
timeout, frozen heights, or `block_sync_request_emitted=0` on a lagging
replica is a failure to investigate.

### B6. 4-node BLS chain happy path — 3 seeds

Repeat A6 across seeds `7 42 113`, fresh workdir each
(`/tmp/regression-runs/b6-$SEED`). Same pass criteria as A6: `wait`
exit 0 and `verify-safety` exit 0 every trial. Variance signal worth
flagging: per-trial commit-height spread at the wait deadline. BLS
keygen + PoP work runs once per node at `new` time and shouldn't
materially affect post-warmup throughput; consistent height drift
across seeds means CPU contention on the runner, not a BLS path bug.

**If the budget is 30 min, stop here and write the report.**

---

## Tier C: extended depth (60+)

Adds ~25 min on top of Tier B. Two heavier probes that catch failures
the smaller sweeps miss.

### C1. 7-node `rotating-failure-7n-f2` with partition probe — 3 seeds

The built-in `rotating-failure-7n-f2` scenario auto-tears-down on a
wedge, which destroys the gossip-mesh state we need for the partition
probe. Drive its shape manually so the cluster stays up after the wedge.

For seed in `1 42 107`:

```sh
WD=/tmp/regression-runs/c1-$SEED
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

**(A) `WAIT_EXIT == 0` — survivors progressed.** Pass. Tear down.

**(B) `WAIT_EXIT != 0` — survivors wedged.** Don't classify as a failure
yet. Run the partition probe:

1. Read `state.json` to get each surviving validator's `node_id` and
   `api_addr`.
2. For each survivor, `curl http://$api_addr/peers` → list of base58
   NodeIds.
3. Build an undirected graph on the survivor NodeId set (edge `A–B` if
   `B` appears in `A`'s peer list *or* `A` appears in `B`'s — `/peers`
   only shows direct connections; either-direction is sufficient).
4. BFS from any survivor: if every other survivor is reachable,
   `PARTITIONED=false`; otherwise `PARTITIONED=true`.
5. Read `consensus.timeout_max_ms` from `$WD/node1/config.toml`. Set
   `HALT_SECS = timeout_max_ms × 3 / 1000` (default → 30 s).

Then:

- **`PARTITIONED=false` + wedge → real bug.** Honest 5-of-7 quorum had
  full mesh connectivity, so partial-synchrony required progress and
  none happened. Capture: snap, verify-safety exit, telemetry, last 30
  lines of `testnet logs <node>` for the lowest-height survivor,
  `bootstrap_peers` from `state.json`, and the per-survivor `/peers`
  dump. Tear down.

- **`PARTITIONED=true` + wedge → expected partial-sync stall, probe
  recovery:**

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

  - `RECOVER_EXIT == 0`: pass with caveat — note the seed
    graph-partitioned the survivor subgraph (a gossip cold-start
    bound, not a consensus bug); cluster recovered once the partition
    healed.
  - `RECOVER_EXIT != 0`: real bug in the recovery path. Capture full
    diagnostics.

Pass condition: `verify-safety` exit 0 in every branch, *and* either
(A), or (B) terminating in `RECOVER_EXIT == 0`.

### C2. 3-of-4 sequential-kill restart — 10 seeds

Stress shape that exercises post-restart liveness with the lowest-view
replica restarted first. Tighter timeouts force more view changes.

For seed in `1 7 11 13 17 23 29 42 50 64`:

```sh
WD=/tmp/regression-runs/c2-$SEED
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
$TESTNET wait --all-reach-height $((PRE_H+10)) --workdir $WD --timeout 120
WAIT_EXIT=$?
$TESTNET snap --workdir $WD
$TESTNET verify-safety --workdir $WD
$TESTNET telemetry --workdir $WD
$TESTNET down --workdir $WD
[ $WAIT_EXIT -eq 0 ] && rm -rf $WD     # preserve workdir on failure
```

Pass condition: `wait` exit 0 *and* `verify-safety` exit 0.

For any failure, capture: snap, verify-safety exit, telemetry, last 30
lines of `testnet logs <node>` for the lowest-height node,
`bootstrap_peers` from `state.json`. Note which node is stuck and at
what `(view, last_committed_height)` it sits, and whether
`block_sync_request_emitted` is zero or non-zero on the stuck node.

**If the budget is 60 min, stop here and write the report.**

---

## Tier D: full sweeps (90)

Replaces B5 / C1 / C2 with their full-size variants. Adds ~30 min on
top of Tier C.

### D1. C1 expanded — 5 seeds

Run C1 against seeds `1 7 42 102 107` (instead of 3).

### D2. B5 expanded — 20 seeds

Run B5 against seeds
`1 7 11 13 17 23 29 42 50 64 73 89 97 100 102 107 113 127 131 149`
(instead of 5). At 5% intermittent rate, 20 trials yields ~1 expected
failure; at 20% rate, ~4. Smaller samples bury intermittents.

### D3. C2 expanded — 20 seeds

Run C2 against the same 20 seeds as D2.

---

## Reporting

A structured summary with one row per scenario group actually run:

| Scenario | Trials run | Passes | Failures | Notes |

For C1/D1 specifically, additionally classify each trial's branch:

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
- Per-node `/consensus/status` `.backpressure` block from the
  back-pressure check (both samples if the trial took two).
- Last 30 lines of `testnet logs <node>` for the most-stuck node
  (lowest height).
- `bootstrap_peers` from `state.json` if relevant.
- For C1/D1 `unpartitioned-wedge` failures: the per-survivor `/peers`
  dump that established the survivor subgraph was connected.

A one-line aggregate verdict at the top: **all pass** or **N trials
failed across <which scenarios>**, plus the budget tier that was run so
the reader knows what coverage the verdict reflects.

Flag explicitly whether B4a's failure mode matched expectation; that's
documented behaviour, not a bug.

## Don't

- Don't commit, push, open issues, or post comments. Observe-only.
- Don't reduce seed counts within a tier to save time. If you're tight
  on budget, drop to a lower tier instead — the seed counts in each
  tier are calibrated for that tier's coverage claim.
- Don't skip `verify-safety` even on apparent passes. A silent safety
  violation matters more than a wedge.
- Don't try to diagnose root causes. Just capture and report what's
  observable. Pattern-matching to known-bug signatures is fine and
  useful in the notes column, but the verdict is observational.

## Wall-time guide

| Tier | Build | Testing | Total |
| --- | --- | --- | --- |
| 15 min | ~3–4 min | ~6–10 min | ~10–14 min |
| 30 min | ~3–4 min | ~20–25 min | ~25–30 min |
| 60 min | ~3–4 min | ~50 min | ~55 min |
| 90 min | ~3–4 min | ~80–85 min | ~90 min |

Each failed `wait` burns 30–120 s of dead time. C2/D3 trials are
~65 s each on the happy path (5 s warmup + 30 s delay + ~30 s typical
catch-up); the recovery `--timeout` is set to 120 s to absorb runner-load
tail latency without spuriously timing out. Run sweeps in series unless
your harness handles concurrent testnet workdirs cleanly.

Report in under 800 words plus the verbatim failure dumps.
