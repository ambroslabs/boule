use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use crate::gossip::store::GossipStore;

pub async fn run(
    store: Arc<GossipStore>,
    interval_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.tick().await; // discard the immediate first tick

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let removed = store.remove_expired();
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
