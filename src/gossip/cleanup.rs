use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use crate::clock::Clock;
use crate::gossip::store::GossipStore;

pub async fn run(
    store: Arc<GossipStore>,
    interval_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    clock: Arc<dyn Clock>,
) {
    let mut interval = clock.interval(Duration::from_secs(interval_secs));
    interval.tick().await; // discard the immediate first tick

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // `expiry` is an absolute wall-clock timestamp serialized on
                // the wire, so this is timestamp comparison, not duration
                // math. Consensus-adjacent code must use
                // [`Clock::now_monotonic`] for any `t2 - t1` style math.
                let removed = store.remove_expired(clock.now_wall());
                if removed > 0 {
                    info!("cleanup removed {removed} expired messages");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}
