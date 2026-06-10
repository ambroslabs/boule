use sha2::{Digest, Sha256};

use crate::View;
use crate::bls_key_history::BlsKeyHistory;
use crate::operator_key_history::OperatorKeyHistory;
use crate::replication::block::Block;
use crate::validator_history::ValidatorSetHistory;
use crate::validator_key_history::ValidatorKeyHistory;
use crate::validator_set::{Pubkey, ValidatorSet};
use boule_core::crypto::signed::ChainId;

#[derive(Debug)]
pub enum RotationCancelError {
    Malformed(String),

    UnknownValidator,

    NoPendingRotation,

    Verify(crate::validator_rotation::RotationVerifyError),

    History(crate::validator_key_history::HistoryError),
}

impl std::fmt::Display for RotationCancelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "rotation-cancel payload malformed: {e}"),
            Self::UnknownValidator => {
                f.write_str("rotation-cancel references an unknown validator")
            }
            Self::NoPendingRotation => {
                f.write_str("no pending rotation matches the cancel's v_eff")
            }
            Self::Verify(e) => write!(f, "rotation-cancel signature verification failed: {e}"),
            Self::History(e) => write!(f, "rotation-cancel history removal failed: {e}"),
        }
    }
}

impl std::error::Error for RotationCancelError {}

pub fn apply_rotation_cancel_command(
    key_history: &mut ValidatorKeyHistory,
    bls_key_history: Option<&mut BlsKeyHistory>,
    cmd_bytes: &[u8],
    chain_id: &ChainId,
    commit_view: View,
) -> Result<bool, RotationCancelError> {
    use crate::validator_rotation::DualSignedRotationCancel;

    if !DualSignedRotationCancel::is_cancel_payload(cmd_bytes) {
        return Ok(false);
    }
    let cancel = DualSignedRotationCancel::decode_command(cmd_bytes)
        .map_err(|e| RotationCancelError::Malformed(e.to_string()))?;
    let validator_pk = Pubkey::from_node_id(cancel.payload.validator);
    let cancelling_v_eff = cancel.payload.cancelling_v_eff;

    let pending_new = key_history
        .pending_rotation_new_key(&validator_pk, cancelling_v_eff, commit_view)
        .ok_or(RotationCancelError::NoPendingRotation)?;

    let stable = key_history
        .validator_for(&validator_pk)
        .ok_or(RotationCancelError::UnknownValidator)?;
    let current_key = key_history
        .key_at(&stable, commit_view)
        .ok_or(RotationCancelError::UnknownValidator)?;

    cancel
        .verify(current_key.as_node_id(), pending_new.as_node_id(), chain_id)
        .map_err(RotationCancelError::Verify)?;

    key_history
        .cancel_pending_rotation(&validator_pk, cancelling_v_eff, commit_view)
        .map_err(RotationCancelError::History)?;

    if let Some(bls) = bls_key_history {
        let _ = bls.cancel_pending_rotation(stable.into_node_id(), cancelling_v_eff, commit_view);
    }
    Ok(true)
}

#[derive(Debug)]
pub enum OperatorRotationError {
    Malformed(String),

    UnknownValidator,

    NoOperatorKey,

    Verify(crate::validator_rotation::RotationVerifyError),

    Scheme(crate::validator_rotation::RotationStructuralError),

    History(crate::validator_key_history::HistoryError),
}

impl std::fmt::Display for OperatorRotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "operator-rotation payload malformed: {e}"),
            Self::UnknownValidator => {
                f.write_str("operator-rotation references an unknown validator")
            }
            Self::NoOperatorKey => {
                f.write_str("operator-rotation: validator has no operator key on file")
            }
            Self::Verify(e) => write!(f, "operator-rotation signature verification failed: {e}"),
            Self::Scheme(e) => write!(f, "operator-rotation scheme-consistency failed: {e}"),
            Self::History(e) => write!(f, "operator-rotation history apply failed: {e}"),
        }
    }
}

impl std::error::Error for OperatorRotationError {}

pub fn apply_operator_rotation_command(
    key_history: &mut ValidatorKeyHistory,
    bls_key_history: Option<&mut BlsKeyHistory>,
    operator_key_history: &OperatorKeyHistory,
    cmd_bytes: &[u8],
    chain_id: &ChainId,
    commit_view: View,
) -> Result<bool, OperatorRotationError> {
    use crate::validator_rotation::OperatorSignedRotation;

    if !OperatorSignedRotation::is_operator_rotation_payload(cmd_bytes) {
        return Ok(false);
    }
    let env = OperatorSignedRotation::decode_command(cmd_bytes)
        .map_err(|e| OperatorRotationError::Malformed(e.to_string()))?;

    let validator_pk = Pubkey::from_node_id(env.payload.validator);
    let stable = key_history
        .validator_for(&validator_pk)
        .ok_or(OperatorRotationError::UnknownValidator)?;

    let operator_pk = operator_key_history
        .key_at(&stable, commit_view)
        .ok_or(OperatorRotationError::NoOperatorKey)?;

    env.verify(&operator_pk, chain_id)
        .map_err(OperatorRotationError::Verify)?;

    env.payload
        .validate_scheme_consistency(chain_id)
        .map_err(OperatorRotationError::Scheme)?;

    key_history
        .apply_rotation(&env.payload, commit_view)
        .map_err(OperatorRotationError::History)?;

    if let (Some(bls), Some(new_bls_pk)) = (bls_key_history, env.payload.new_bls_pubkey) {
        let _ = bls.apply_rotation(stable.into_node_id(), env.payload.v_eff, new_bls_pk);
    }
    Ok(true)
}

#[derive(Debug)]
pub enum OperatorKeyRotationError {
    Malformed(String),

    NoOperatorKey,

    Verify(crate::validator_rotation::RotationVerifyError),

    History(crate::operator_key_history::OperatorHistoryError),
}

impl std::fmt::Display for OperatorKeyRotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "operator-key-rotation payload malformed: {e}"),
            Self::NoOperatorKey => {
                f.write_str("operator-key-rotation: validator has no operator key on file")
            }
            Self::Verify(e) => {
                write!(
                    f,
                    "operator-key-rotation signature verification failed: {e}"
                )
            }
            Self::History(e) => write!(f, "operator-key-rotation history apply failed: {e}"),
        }
    }
}

impl std::error::Error for OperatorKeyRotationError {}

pub fn apply_operator_key_rotation_command(
    operator_key_history: &mut OperatorKeyHistory,
    cmd_bytes: &[u8],
    chain_id: &ChainId,
    commit_view: View,
) -> Result<bool, OperatorKeyRotationError> {
    use crate::validator_rotation::DualSignedOperatorRotation;

    if !DualSignedOperatorRotation::is_operator_key_rotation_payload(cmd_bytes) {
        return Ok(false);
    }
    let env = DualSignedOperatorRotation::decode_command(cmd_bytes)
        .map_err(|e| OperatorKeyRotationError::Malformed(e.to_string()))?;

    let validator = crate::validator_set::ValidatorId::from_genesis_pubkey(env.payload.validator);

    let current_operator = operator_key_history
        .key_at(&validator, commit_view)
        .ok_or(OperatorKeyRotationError::NoOperatorKey)?;

    env.verify(&current_operator, chain_id)
        .map_err(OperatorKeyRotationError::Verify)?;

    operator_key_history
        .apply_rotation(
            &validator,
            env.payload.v_eff,
            env.payload.new_operator_pubkey,
        )
        .map_err(OperatorKeyRotationError::History)?;
    Ok(true)
}

const DOMAIN_V1: &[u8] = b"boule.history_commitment.v1";

pub fn validator_history_commitment_v1(
    set_history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    bls_key_history: Option<&BlsKeyHistory>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(DOMAIN_V1);

    let set_bytes = postcard::to_stdvec(&set_history.to_persisted())
        .expect("postcard encoding of PersistedValidatorHistory cannot fail");
    feed_section(&mut hasher, &set_bytes);

    let key_bytes = postcard::to_stdvec(&key_history.to_persisted())
        .expect("postcard encoding of PersistedValidatorKeyHistory cannot fail");
    feed_section(&mut hasher, &key_bytes);

    match bls_key_history {
        Some(bls) => {
            hasher.update([1u8]);
            let bls_bytes = postcard::to_stdvec(&bls.to_persisted())
                .expect("postcard encoding of PersistedBlsKeyHistory cannot fail");
            feed_section(&mut hasher, &bls_bytes);
        }
        None => {
            hasher.update([0u8]);
        }
    }

    hasher.finalize().into()
}

const DOMAIN_V2: &[u8] = b"boule.history_commitment.v2";

pub fn validator_history_commitment_v2(
    set_history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    bls_key_history: Option<&BlsKeyHistory>,
    operator_key_history: Option<&OperatorKeyHistory>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_V2);

    let set_bytes = postcard::to_stdvec(&set_history.to_persisted())
        .expect("postcard encoding of PersistedValidatorHistory cannot fail");
    feed_section(&mut hasher, &set_bytes);

    let key_bytes = postcard::to_stdvec(&key_history.to_persisted())
        .expect("postcard encoding of PersistedValidatorKeyHistory cannot fail");
    feed_section(&mut hasher, &key_bytes);

    match bls_key_history {
        Some(bls) => {
            hasher.update([1u8]);
            let bls_bytes = postcard::to_stdvec(&bls.to_persisted())
                .expect("postcard encoding of PersistedBlsKeyHistory cannot fail");
            feed_section(&mut hasher, &bls_bytes);
        }
        None => {
            hasher.update([0u8]);
        }
    }

    let op_persisted = operator_key_history
        .map(|op| op.to_persisted())
        .unwrap_or_default();
    let op_bytes = postcard::to_stdvec(&op_persisted)
        .expect("postcard encoding of PersistedOperatorKeyHistory cannot fail");
    feed_section(&mut hasher, &op_bytes);

    hasher.finalize().into()
}

fn feed_section(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[allow(clippy::too_many_arguments)]
pub fn apply_reconfig_commands_to_set_history(
    block: &Block,
    set_history: &mut ValidatorSetHistory,
    key_history: &mut ValidatorKeyHistory,
    mut operator_key_history: Option<&mut OperatorKeyHistory>,
    mut bls_key_history: Option<&mut BlsKeyHistory>,
    min_v_eff_delay: View,
    chain_id: &ChainId,
) {
    use crate::reconfig::ReconfigCommand;

    let block_view = block.header.view;
    for cmd_bytes in &block.commands {
        if !ReconfigCommand::is_reconfig_payload(cmd_bytes) {
            continue;
        }
        let cmd = match ReconfigCommand::decode(cmd_bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let current_set_at = set_history.set_at(block_view);
        let next_members = match cmd.validate_against_with_delay_and_chain(
            current_set_at.for_view(block_view),
            block_view,
            min_v_eff_delay,
            chain_id,
        ) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let conflict = set_history
            .iter()
            .any(|(v_eff, _)| v_eff != View::ZERO && v_eff > block_view);
        if conflict {
            continue;
        }

        let next_entries: Vec<(crate::validator_set::ValidatorId, u64)> = next_members
            .into_iter()
            .map(|(n, w)| (crate::validator_set::ValidatorId::from_genesis_pubkey(n), w))
            .collect();
        let new_set = match ValidatorSet::with_weights(next_entries) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let new_members: Vec<crate::validator_set::ValidatorId> = new_set.iter().copied().collect();
        if set_history.insert_boundary(cmd.v_eff, new_set).is_err() {
            continue;
        }

        for member in &new_members {
            if !key_history.validators().any(|id| id == *member) {
                let pubkey = crate::validator_set::Pubkey::from_node_id(member.into_node_id());
                let _ = key_history.add_validator(pubkey, cmd.v_eff);
            }
        }

        if let Some(op_hist) = operator_key_history.as_deref_mut() {
            for entry in &cmd.adds {
                let Some(operator_pubkey) = entry.operator_pubkey else {
                    continue;
                };
                let v_id = crate::validator_set::ValidatorId::from_genesis_pubkey(entry.node_id);
                if new_members.contains(&v_id) && !op_hist.contains(&v_id) {
                    let _ = op_hist.register(&v_id, cmd.v_eff, operator_pubkey);
                }
            }
        }

        if let Some(bls_hist) = bls_key_history.as_deref_mut() {
            for entry in &cmd.adds {
                let Some(bls_pop) = &entry.bls_pop else {
                    continue;
                };
                let v_id = crate::validator_set::ValidatorId::from_genesis_pubkey(entry.node_id);
                if new_members.contains(&v_id) && !bls_hist.contains(&entry.node_id) {
                    let _ = bls_hist.register(entry.node_id, cmd.v_eff, bls_pop.pubkey);
                }
            }
        }
    }
}

pub fn apply_rotation_commands_to_histories(
    block: &Block,
    _set_history: &ValidatorSetHistory,
    key_history: &mut ValidatorKeyHistory,
    mut bls_key_history: Option<&mut BlsKeyHistory>,
    operator_key_history: Option<&mut OperatorKeyHistory>,
    chain_id: &ChainId,
) {
    use crate::validator_rotation::DualSignedRotation;

    let block_view = block.header.view;
    for cmd_bytes in &block.commands {
        if !DualSignedRotation::is_rotation_payload(cmd_bytes) {
            continue;
        }
        let envelope = match DualSignedRotation::decode_command(cmd_bytes) {
            Ok(env) => env,
            Err(_) => continue,
        };

        let validator_pk = crate::validator_set::Pubkey::from_node_id(envelope.payload.validator);
        let current_key = match key_history.current_key(&validator_pk) {
            Some(k) => k,
            None => continue,
        };

        if envelope.verify(current_key.as_node_id(), chain_id).is_err() {
            continue;
        }

        if envelope
            .payload
            .validate_scheme_consistency(chain_id)
            .is_err()
        {
            continue;
        }

        let stable_id = key_history.validator_for(&validator_pk);

        if key_history
            .apply_rotation(&envelope.payload, block_view)
            .is_err()
        {
            continue;
        }

        let new_bls_pk = match envelope.payload.new_bls_pubkey {
            Some(pk) => pk,
            None => {
                continue;
            }
        };
        let bls_history = match bls_key_history.as_deref_mut() {
            Some(h) => h,
            None => {
                continue;
            }
        };
        let stable_id = match stable_id {
            Some(id) => id,
            None => continue,
        };

        let _ = bls_history.apply_rotation(
            stable_id.into_node_id(),
            envelope.payload.v_eff,
            new_bls_pk,
        );
    }

    for cmd_bytes in &block.commands {
        let _ = apply_rotation_cancel_command(
            key_history,
            bls_key_history.as_deref_mut(),
            cmd_bytes,
            chain_id,
            block_view,
        );
    }

    if let Some(op) = operator_key_history.as_deref() {
        for cmd_bytes in &block.commands {
            let _ = apply_operator_rotation_command(
                key_history,
                bls_key_history.as_deref_mut(),
                op,
                cmd_bytes,
                chain_id,
                block_view,
            );
        }
    }

    if let Some(op) = operator_key_history {
        for cmd_bytes in &block.commands {
            let _ = apply_operator_key_rotation_command(op, cmd_bytes, chain_id, block_view);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn compute_post_block_commitment(
    block: &Block,
    set_history: &ValidatorSetHistory,
    key_history: &ValidatorKeyHistory,
    bls_key_history: Option<&BlsKeyHistory>,
    operator_key_history: Option<&OperatorKeyHistory>,
    chain_id: &ChainId,
    min_v_eff_delay: View,
) -> [u8; 32] {
    let mut set = set_history.clone();
    let mut key = key_history.clone();
    let mut bls = bls_key_history.cloned();

    let mut operator = operator_key_history.cloned();
    apply_reconfig_commands_to_set_history(
        block,
        &mut set,
        &mut key,
        operator.as_mut(),
        bls.as_mut(),
        min_v_eff_delay,
        chain_id,
    );
    apply_rotation_commands_to_histories(
        block,
        &set,
        &mut key,
        bls.as_mut(),
        operator.as_mut(),
        chain_id,
    );
    validator_history_commitment_v2(&set, &key, bls.as_ref(), operator.as_ref())
}
