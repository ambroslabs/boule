//! End-to-end exercise of the testnet driver lib (`ambros_p2p::testnet`):
//! 4-node cluster, drive it through `new` → `up` → wait → kill → wait →
//! verify-safety → `down`. Uses the `ambros-p2p` binary built by cargo
//! (`CARGO_BIN_EXE_ambros-p2p`) so we exercise the same spawn path the
//! `testnet` CLI does.
//!
//! Budgeted for the 15s/test ceiling in CLAUDE.md: the cluster runs at
//! `timeout_base_ms = 200` so commits land in well under a second.

use std::path::PathBuf;
use std::time::Duration;

use ambros_p2p::testnet::{lifecycle, safety, topology, wait, workdir};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn driver_lifecycle_4_nodes() {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ambros-p2p"));
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
