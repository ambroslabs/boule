use std::sync::Arc;

use bytes::Bytes;

pub trait CommandValidator: Send + Sync {
    fn check(&self, cmd: &[u8]) -> anyhow::Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAllValidator;

impl CommandValidator for AcceptAllValidator {
    fn check(&self, _cmd: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
}

pub trait StateMachine: Send + Sync {
    fn check(&self, _cmd: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }

    fn validator(&self) -> Arc<dyn CommandValidator> {
        Arc::new(AcceptAllValidator)
    }

    fn apply(&mut self, cmd: &[u8]) -> anyhow::Result<Bytes>;

    fn state_commitment(&self) -> [u8; 32];

    fn snapshot(&self) -> Bytes;

    fn restore(&mut self, snap: &[u8]) -> anyhow::Result<()>;
}
