use bytes::Bytes;

pub trait Mempool: Send + Sync {
    fn insert(&self, cmd: Bytes) -> anyhow::Result<bool>;

    fn propose(&self, limit: usize) -> Vec<Bytes>;

    fn remove_committed(&self, cmds: &[Bytes]);

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
