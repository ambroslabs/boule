#![allow(dead_code)]
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::View;

pub struct ViewTimer {
    fired_tx: mpsc::Sender<View>,

    current: Option<(View, JoinHandle<()>)>,
}

impl ViewTimer {
    pub fn new(fired_tx: mpsc::Sender<View>) -> Self {
        Self {
            fired_tx,
            current: None,
        }
    }

    pub fn reset(&mut self, view: View, duration: Duration) {
        self.cancel();

        let tx = self.fired_tx.clone();
        let handle = tokio::spawn(async move {
            sleep(duration).await;

            let _ = tx.send(view).await;
        });
        self.current = Some((view, handle));
    }

    pub fn cancel(&mut self) {
        if let Some((_, handle)) = self.current.take() {
            handle.abort();
        }
    }

    pub fn armed_for(&self) -> Option<View> {
        self.current.as_ref().map(|(v, _)| *v)
    }
}

impl Drop for ViewTimer {
    fn drop(&mut self) {
        self.cancel();
    }
}
