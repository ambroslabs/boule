use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    ProposalReceived(crate::dispatch::Verified<Signed<Proposal>>),

    VoteReceived(VoteVariant),

    NewViewReceived(crate::dispatch::Verified<Signed<NewView>>),

    PacemakerAdvance(View),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteVariant {
    signed: crate::dispatch::Verified<Signed<Vote>>,
    partial: BlsPartialSig,
}

impl VoteVariant {
    pub fn verified(&self) -> &crate::dispatch::Verified<Signed<Vote>> {
        &self.signed
    }

    pub fn from_optional_partial(
        signed: crate::dispatch::Verified<Signed<Vote>>,
        bls_partial: Option<BlsPartialSig>,
    ) -> Self {
        Self {
            signed,
            partial: bls_partial
                .expect("BLS vote must carry a partial after verify_bls_partial_if_required"),
        }
    }

    pub fn new(signed: crate::dispatch::Verified<Signed<Vote>>, partial: BlsPartialSig) -> Self {
        Self { signed, partial }
    }

    pub fn into_parts(self) -> (crate::dispatch::Verified<Signed<Vote>>, BlsPartialSig) {
        (self.signed, self.partial)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateUpdate {
    VotedInView { view: View },

    Locked(Locked),

    HighQc(QuorumCertificate),

    ProposedInView { view: View },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Broadcast(ConsensusMsg),

    Persist(StateUpdate),

    Commit(Block),

    RequestBlock {
        hash: BlockHash,
        peer: NodeId,
        expected_height: Height,
        reason: BlockSyncReason,
    },

    EquivocationEvidence {
        voter: ValidatorId,
        view: View,
        block_a: BlockHash,
        block_b: BlockHash,
    },

    ProposalEquivocationEvidence {
        leader: ValidatorId,
        view: View,
        block_a: BlockHash,
        block_b: BlockHash,
    },

    BuildProposal {
        view: View,
        high_qc: QuorumCertificate,
        parent: Block,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSyncReason {
    UnknownParentOnProposal,

    StillParkedOnPacemakerAdvance,

    UnknownHighQcOnNewView,

    RetryTimerTick,
}

impl BlockSyncReason {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockSyncReason::UnknownParentOnProposal => "unknown_parent_on_proposal",
            BlockSyncReason::StillParkedOnPacemakerAdvance => "still_parked_on_pacemaker_advance",
            BlockSyncReason::UnknownHighQcOnNewView => "unknown_high_qc_on_new_view",
            BlockSyncReason::RetryTimerTick => "retry_timer_tick",
        }
    }
}

pub trait BlockBuilder: Send + Sync {
    fn build(
        &self,
        parent: &Block,
        view: View,
        high_qc: &QuorumCertificate,
        pending_blocks: &HashMap<BlockHash, Block>,
        timestamp: u64,
    ) -> anyhow::Result<Block>;
}
