use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{error, info};

use super::manager::ManagerMsg;

pub async fn run(listener: TcpListener, manager_tx: mpsc::Sender<ManagerMsg>) {
    info!("TCP listener started on {}", listener.local_addr().unwrap());
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("inbound connection from {addr}");
                let _ = manager_tx.send(ManagerMsg::NewConnection { stream, addr }).await;
            }
            Err(e) => {
                error!("accept error: {e}");
            }
        }
    }
}
