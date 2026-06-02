//! End-to-end exercise of the testnet driver lib (`boule_core::testnet`):
//! 4-node cluster, drive it through `new` → `up` → wait → kill → wait →
//! verify-safety → `down`. Uses the `boule` binary built by cargo
//! (`CARGO_BIN_EXE_boule`) so we exercise the same spawn path the
//! `testnet` CLI does.
//!
//! Budgeted for the 15s/test ceiling in CLAUDE.md: the cluster runs at
//! `timeout_base_ms = 200` so commits land in well under a second.

use std::path::PathBuf;
use std::time::Duration;

use boule_node::testnet::{lifecycle, safety, scenario, topology, wait, workdir};
use tokio::sync::Mutex;

/// Serializes every test in this file. Each test spawns a 4-node
/// `boule` cluster (process-level spawn + addr-file discovery +
/// consensus warm-up); running multiple in parallel on a hosted
/// runner times out under CPU contention. Held across awaits, so it
/// must be a tokio (async) mutex — `std::sync::Mutex` would trip the
/// `await_holding_lock` lint.
static TEST_SERIAL: Mutex<()> = Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn driver_lifecycle_4_nodes() {
    let _serial = TEST_SERIAL.lock().await;
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_boule"));
    let tmp = tempfile::tempdir().expect("tempdir");
    let wd = tmp.path().to_path_buf();

    let spec = topology::TopologySpec {
        nodes: 4,
        seed_extra: 0,
        target_degree: 3,
        seed: 7,
    };

    let state = lifecycle::new_cluster(lifecycle::NewArgs {
        workdir: wd.clone(),
        spec,
        binary: bin.clone(),
        timeout_base_ms: 200,
        timeout_max_ms: 1_500,
        signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected,
    })
    .await
    .expect("new_cluster");
    assert_eq!(state.nodes.len(), 4);
    for n in &state.nodes {
        assert!(
            n.node_id.is_some(),
            "node_id missing for {}",
            n.display_name()
        );
        assert!(
            n.api_addr.is_some(),
            "api_addr missing for {}",
            n.display_name()
        );
    }

    let pids = lifecycle::up_all(&wd, &bin, &state).await.expect("up_all");
    assert_eq!(pids.len(), 4);

    // Bring-up complete: every live node should commit at least 2
    // blocks within the budget.
    wait::all_reach_height(&state, 2, Duration::from_secs(6))
        .await
        .expect("all_reach_height(2) before kill");

    // Kill one node; the remaining three are still 2f+1 = 3 with f=1
    // and should keep making progress.
    let target = state.nodes[1].clone();
    lifecycle::kill_one(&wd, &target).expect("kill_one");
    assert!(
        lifecycle::pid_alive(&target).is_none(),
        "{} should be down after kill",
        target.display_name()
    );

    // Survivors keep committing. `all_reach_height` filters to live
    // nodes via `pid_alive`, so the dead node doesn't gate the wait.
    let state_after_kill = workdir::State::load(&wd).expect("reload state");
    wait::all_reach_height(&state_after_kill, 4, Duration::from_secs(4))
        .await
        .expect("all_reach_height(4) after kill — survivors should keep committing");

    // No two live nodes ever committed a different view at the same
    // height (the §8 safety check, ANSI-tolerant).
    let violations = safety::verify(&state_after_kill).expect("safety::verify");
    assert!(
        violations.is_empty(),
        "expected zero safety violations, got {} entries",
        violations.len()
    );

    // Tear down — must leave no live processes behind.
    lifecycle::down(&wd, &state_after_kill).expect("down");
    for n in &state_after_kill.nodes {
        assert!(
            lifecycle::pid_alive(n).is_none(),
            "{} still alive after down",
            n.display_name()
        );
    }
}

/// End-to-end tx ingress: a transaction submitted over `POST
/// /mempool/submit` to a running cluster is committed. Proves the
/// submission endpoint admits a command and the cluster carries it through
/// propose → commit (observable as every node draining it from its mempool,
/// which only happens on commit, with none dropped).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submitted_tx_is_committed() {
    use boule_consensus::replication::impls::counter_sm::CounterCommand;
    use boule_node::testnet::admin;

    let _serial = TEST_SERIAL.lock().await;
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_boule"));
    let tmp = tempfile::tempdir().expect("tempdir");
    let wd = tmp.path().to_path_buf();

    let spec = topology::TopologySpec {
        nodes: 4,
        seed_extra: 0,
        target_degree: 3,
        seed: 11,
    };
    let state = lifecycle::new_cluster(lifecycle::NewArgs {
        workdir: wd.clone(),
        spec,
        binary: bin.clone(),
        timeout_base_ms: 200,
        timeout_max_ms: 1_500,
        signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected,
    })
    .await
    .expect("new_cluster");
    let _pids = lifecycle::up_all(&wd, &bin, &state).await.expect("up_all");

    wait::all_reach_height(&state, 2, Duration::from_secs(6))
        .await
        .expect("warm-up commits before submitting");

    // Submit a valid counter command to every node's ingress endpoint.
    // Submitting to all nodes means whichever validator leads next picks it
    // up — there is no cross-validator tx gossip yet, so a tx only reaches a
    // block via the mempool of a node that leads.
    let cmd = CounterCommand::Increment.encode().to_vec();
    let http = reqwest::Client::new();
    for n in &state.nodes {
        let api = n.api_addr.expect("api_addr");
        let resp = http
            .post(format!("http://{api}/mempool/submit"))
            .body(cmd.clone())
            .send()
            .await
            .expect("submit request");
        assert_eq!(
            resp.status().as_u16(),
            202,
            "{} should accept the submitted tx",
            n.display_name(),
        );
    }

    // The command must be committed, not dropped: every node drains it from
    // its mempool (remove_committed runs only on commit) and the leader-side
    // includability check did not reject it.
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    loop {
        let mut all_drained = true;
        for n in &state.nodes {
            let api = n.api_addr.expect("api_addr");
            let st = admin::consensus_status(api).await.expect("status");
            assert_eq!(
                st.dropped_commands,
                0,
                "{} dropped a valid submitted command",
                n.display_name(),
            );
            if st.mempool_size != 0 {
                all_drained = false;
            }
        }
        if all_drained {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "submitted tx was not committed (drained from all mempools) within budget",
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    lifecycle::down(&wd, &state).expect("down");
}

/// End-to-end app-driven validator-set change (#225 M5/M6): a `StakeCommand`
/// submitted over `POST /mempool/submit` makes the demo application return a
/// `validator_update` from `commit`, which the consensus layer materialises
/// as a reconfig — so a submitted tx removes a validator on a live cluster.
/// Exercises the whole app→consensus membership stack (#651/#652) through
/// real tx ingress (#663).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submitted_stake_command_changes_the_validator_set() {
    use boule_core::identity::base58_to_node_id;
    use boule_node::demo_staking::StakeCommand;
    use boule_node::testnet::admin;

    let _serial = TEST_SERIAL.lock().await;
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_boule"));
    let tmp = tempfile::tempdir().expect("tempdir");
    let wd = tmp.path().to_path_buf();

    // 5 nodes so removing one leaves a still-BFT set of 4 (f=1).
    let spec = topology::TopologySpec {
        nodes: 5,
        seed_extra: 0,
        target_degree: 4,
        seed: 13,
    };
    let state = lifecycle::new_cluster(lifecycle::NewArgs {
        workdir: wd.clone(),
        spec,
        binary: bin.clone(),
        timeout_base_ms: 200,
        timeout_max_ms: 1_500,
        signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected,
    })
    .await
    .expect("new_cluster");
    let _pids = lifecycle::up_all(&wd, &bin, &state).await.expect("up_all");

    wait::all_reach_height(&state, 2, Duration::from_secs(6))
        .await
        .expect("warm-up commits");

    // Remove the highest-sorted validator (`validator_set` is ordered), then
    // observe liveness on a node that is still seated.
    let api0 = state.nodes[0].api_addr.expect("api_addr");
    let st0 = admin::consensus_status(api0).await.expect("status");
    assert_eq!(st0.validator_set.len(), 5, "genesis set has 5 validators");
    let removed_b58 = st0
        .validator_set
        .last()
        .expect("non-empty validator set")
        .clone();
    let removed = base58_to_node_id(&removed_b58).expect("decode removed node id");

    // An API of a node that will remain seated, to watch progress afterward.
    let mut obs_api = None;
    for n in &state.nodes {
        let api = n.api_addr.expect("api_addr");
        let st = admin::consensus_status(api).await.expect("status");
        if st.node_id != removed_b58 {
            obs_api = Some(api);
            break;
        }
    }
    let obs_api = obs_api.expect("a node other than the removed one");

    // Submit an app-level stake command (weight 0 = remove) to every node —
    // no cross-validator tx gossip yet, so whichever node leads next must
    // already hold it.
    let cmd = StakeCommand {
        node_id: removed,
        weight: 0,
    }
    .encode()
    .to_vec();
    let http = reqwest::Client::new();
    for n in &state.nodes {
        let api = n.api_addr.expect("api_addr");
        let resp = http
            .post(format!("http://{api}/mempool/submit"))
            .body(cmd.clone())
            .send()
            .await
            .expect("submit request");
        assert_eq!(
            resp.status().as_u16(),
            202,
            "{} should accept the stake tx",
            n.display_name(),
        );
    }

    // The demo app turns the committed stake command into a validator_update,
    // materialised as a reconfig: the active set shrinks to 4 and no longer
    // contains the removed validator, on every node.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut all_reduced = true;
        for n in &state.nodes {
            let api = n.api_addr.expect("api_addr");
            let st = admin::consensus_status(api).await.expect("status");
            if st.validator_set.len() != 4 || st.validator_set.contains(&removed_b58) {
                all_reduced = false;
            }
        }
        if all_reduced {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "validator set did not shrink to 4 (app-driven removal) within budget",
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Liveness under the reduced set: a still-seated node keeps committing.
    let base_h = admin::consensus_status(obs_api)
        .await
        .expect("status")
        .last_committed_height
        .0;
    let live_deadline = std::time::Instant::now() + Duration::from_secs(6);
    loop {
        let h = admin::consensus_status(obs_api)
            .await
            .expect("status")
            .last_committed_height
            .0;
        if h >= base_h + 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < live_deadline,
            "cluster did not keep committing under the reduced validator set",
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    lifecycle::down(&wd, &state).expect("down");
}

/// Issue #205, items 1 and 3 in one test: `Step::Up` is now idempotent
/// (no-op when the node is already alive), and `wait::all_advance_by`
/// gates on *new* commits since the wait started.
///
/// The idempotency check runs a scenario consisting of a single
/// `Step::Up` against a node that's already up — pre-fix this bailed
/// with "node1 already has a pid file at …".
///
/// `wait::all_advance_by` is then driven against the post-kill cluster
/// to confirm survivors keep committing — the meaningful liveness
/// signal `wait::all_reach_height` could not honestly express.
///
/// We bundle both into one cluster to stay under the per-test budget;
/// each test in this file pays a 4-node `new_cluster` discovery tax
/// (~3-4s) that's the bulk of wall-clock time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_up_idempotent_and_wait_advance_by_post_kill() {
    let _serial = TEST_SERIAL.lock().await;
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_boule"));
    let tmp = tempfile::tempdir().expect("tempdir");
    let wd = tmp.path().to_path_buf();

    let spec = topology::TopologySpec {
        nodes: 4,
        seed_extra: 0,
        target_degree: 3,
        seed: 7,
    };
    let state = lifecycle::new_cluster(lifecycle::NewArgs {
        workdir: wd.clone(),
        spec,
        binary: bin.clone(),
        timeout_base_ms: 200,
        timeout_max_ms: 1_500,
        signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected,
    })
    .await
    .expect("new_cluster");
    lifecycle::up_all(&wd, &bin, &state).await.expect("up_all");
    wait::all_reach_height(&state, 2, Duration::from_secs(6))
        .await
        .expect("all_reach_height(2)");

    // Issue #205 item 1: a scenario whose `Step::Up` targets an
    // already-running node must succeed. Pre-fix this bailed because
    // `up_one` rejects an existing pid file; the fix short-circuits in
    // `Step::Up` when `pid_alive` returns Some.
    let scen = scenario::Scenario {
        scenario: scenario::ScenarioMeta {
            seed: Some(0),
            name: Some("up-already-up".into()),
        },
        steps: vec![scenario::Step::Up {
            node: "node1".into(),
        }],
    };
    let outcomes = scenario::run(&wd, &bin, scen)
        .await
        .expect("Step::Up against already-up node should be a no-op");
    assert_eq!(outcomes.len(), 1);
    assert!(
        outcomes[0].detail.contains("already running"),
        "expected 'already running' marker, got detail={:?}",
        outcomes[0].detail,
    );

    // Issue #205 item 3: `wait::all_advance_by` snapshots heights and
    // waits for new progress. After killing node2, the surviving three
    // nodes still form a quorum (f=1 in a 4-node cluster) and must
    // commit `delta` more blocks. `wait::all_reach_height` couldn't
    // distinguish "already past the target before the kill" from
    // "advanced after the kill" — `all_advance_by` does.
    let target = state.nodes[1].clone();
    lifecycle::kill_one(&wd, &target).expect("kill_one");
    let state_after_kill = workdir::State::load(&wd).expect("reload state");
    wait::all_advance_by(&state_after_kill, 3, Duration::from_secs(6))
        .await
        .expect("all_advance_by(3) post-kill — survivors must keep committing");

    let violations = safety::verify(&state_after_kill).expect("safety::verify");
    assert!(
        violations.is_empty(),
        "expected zero safety violations, got {} entries",
        violations.len()
    );
    lifecycle::down(&wd, &state_after_kill).expect("down");
}

/// Issue #205, item 2: `testnet new --workdir <relative>` followed by
/// any other subcommand from a different cwd used to fail with
/// "opening log testnet7/node1/log: No such file or directory" because
/// `state.json` recorded cwd-relative paths. The fix canonicalizes
/// `workdir` inside `new_cluster` before computing per-node paths.
///
/// We exercise the relative-workdir code path by setting cwd to a
/// temporary parent and passing a relative subdir. A `CwdGuard`
/// restores cwd on panic so a failed assertion doesn't bleed into
/// other tests. The assertion is structural (paths are absolute) —
/// running the cluster after the chdir would over-budget the test
/// without exercising additional invariants.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_cluster_canonicalizes_relative_workdir() {
    let _serial = TEST_SERIAL.lock().await;
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_boule"));
    let tmp = tempfile::tempdir().expect("tempdir");

    let prev = std::env::current_dir().expect("current_dir");
    let _guard = CwdGuard { prev: prev.clone() };
    std::env::set_current_dir(tmp.path()).expect("set_current_dir tmp");

    let spec = topology::TopologySpec {
        nodes: 4,
        seed_extra: 0,
        target_degree: 3,
        seed: 7,
    };
    let state = lifecycle::new_cluster(lifecycle::NewArgs {
        workdir: PathBuf::from("relwd"),
        spec,
        binary: bin,
        timeout_base_ms: 200,
        timeout_max_ms: 1_500,
        signature_scheme: boule_core::crypto::sig_scheme::SignatureSchemeChoice::Ed25519Collected,
    })
    .await
    .expect("new_cluster with relative workdir");

    // Restore cwd before asserting so the absolute-path invariant is
    // checked against the post-restore state — that's the user-visible
    // scenario (`new` from one cwd, subsequent subcommands from
    // another).
    std::env::set_current_dir(&prev).expect("restore cwd");

    for n in &state.nodes {
        for (label, path) in [
            ("config_path", &n.config_path),
            ("log_path", &n.log_path),
            ("key_path", &n.key_path),
            ("consensus_dir", &n.consensus_dir),
            ("addr_path", &n.addr_path),
        ] {
            assert!(
                path.is_absolute(),
                "{} should be absolute, got {}",
                label,
                path.display()
            );
        }
    }

    // Round-trip through state.json to confirm the on-disk shape also
    // has absolute paths — the relative-cwd bug surfaced when a
    // different cwd reloaded state.json.
    let abs_workdir = std::fs::canonicalize(tmp.path().join("relwd")).expect("canonicalize");
    let reloaded = workdir::State::load(&abs_workdir).expect("State::load");
    for n in &reloaded.nodes {
        assert!(n.log_path.is_absolute(), "reloaded log_path not absolute");
    }
}

/// RAII helper to restore the process's cwd at the end of a test even
/// if it panics. `cargo test` runs tests in a thread pool that shares
/// `cwd`, so a stuck cwd would corrupt unrelated tests.
struct CwdGuard {
    prev: PathBuf,
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prev);
    }
}
