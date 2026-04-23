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
