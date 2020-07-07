use std::slice;
use sgx_types::*;
use anonify_types::*;
use anonify_common::{
    crypto::{UserAddress, AccessRight, Ciphertext},
    traits::*,
    state_types::{MemId, StateType},
};
use anonify_runtime::traits::*;
use anonify_treekem::handshake::HandshakeParams;
use ed25519_dalek::{PublicKey, Signature};
use codec::Decode;
use log::debug;
use anyhow::{Result, anyhow};
use crate::{
    transaction::{JoinGroupTx, EnclaveTx, HandshakeTx, InstructionTx},
    instructions::Instructions,
    notify::updated_state_into_raw,
    bridges::ocalls::save_to_host_memory,
    context::EnclaveContext,
};

pub fn inner_ecall_insert_ciphertext<R, C>(
    ciphertext: *mut u8,
    ciphertext_len: usize,
    raw_updated_state: &mut RawUpdatedState,
    ciphertext_size: usize,
    enclave_context: &C,
) -> Result<()>
where
    R: RuntimeExecutor<C, S=StateType>,
    C: ContextOps<S=StateType> + Clone,
{
    let buf = unsafe{ slice::from_raw_parts_mut(ciphertext, ciphertext_len) };
    let ciphertext = Ciphertext::from_bytes(buf, ciphertext_size);
    let group_key = &mut *enclave_context.get_group_key();

    let iter_op = Instructions::<R, C>::state_transition(enclave_context.clone(), &ciphertext, group_key)?;
    if let Some(updated_state_iter) = iter_op {
        if let Some(updated_state) = enclave_context.update_state(updated_state_iter) {
            *raw_updated_state = updated_state_into_raw(updated_state)?;
        }
    }

    let roster_idx = ciphertext.roster_idx() as usize;
    // ratchet app keychain per a log.
    group_key.ratchet(roster_idx)?;

    Ok(())
}

pub fn inner_ecall_insert_handshake<S: State>(
    handshake: *mut u8,
    handshake_len: usize,
    enclave_context: &EnclaveContext<S>,
) -> Result<()> {
    let handshake_bytes = unsafe { slice::from_raw_parts_mut(handshake, handshake_len) };
    let handshake = HandshakeParams::decode(&mut &handshake_bytes[..])
        .map_err(|_| anyhow!("HandshakeParams::decode Error"))?;
    let group_key = &mut *enclave_context.group_key.write()
        .map_err(|e| anyhow!("{}", e))?;

    group_key.process_handshake(&handshake)?;

    Ok(())
}

pub fn inner_ecall_get_state(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge,
    mem_id: u32,
    state: &mut EnclaveState,
    enclave_context: &EnclaveContext<StateType>,
) -> Result<()> {
    let sig = Signature::from_bytes(&sig[..])
        .map_err(|e| anyhow!("{}", e))?;
    let pubkey = PublicKey::from_bytes(&pubkey[..])
        .map_err(|e| anyhow!("{}", e))?;
    let key = UserAddress::from_sig(&challenge[..], &sig, &pubkey)
        .map_err(|e| anyhow!("{}", e))?;

    let user_state = &enclave_context.get_state(key, MemId::from_raw(mem_id));
    state.0 = save_to_host_memory(&user_state.as_bytes())? as *const u8;

    Ok(())
}

pub fn inner_ecall_join_group<S: State>(
    raw_join_group_tx: &mut RawJoinGroupTx,
    enclave_context: &EnclaveContext<S>,
    ias_url: &str,
    test_sub_key: &str,
) -> Result<()> {
    let join_group_tx = JoinGroupTx::construct(
        ias_url,
        test_sub_key,
        &enclave_context,
    )?;
    *raw_join_group_tx = join_group_tx.into_raw()?;

    Ok(())
}

pub fn inner_ecall_instruction<R, C>(
    raw_sig: &RawSig,
    raw_pubkey: &RawPubkey,
    raw_challenge: &RawChallenge,
    state: *mut u8,
    state_len: usize,
    state_id: u64,
    call_id: u32,
    raw_instruction_tx: &mut RawInstructionTx,
    enclave_context: &EnclaveContext<StateType>,
    max_mem_size: usize,
) -> Result<()>
where
    R: RuntimeExecutor<C, S=StateType>,
    C: ContextOps,
{
    let params = unsafe{ slice::from_raw_parts_mut(state, state_len) };
    let ar = AccessRight::from_raw(*raw_pubkey, *raw_sig, *raw_challenge)
        .map_err(|e| anyhow!("{}", e))?;
    let instruction_tx = InstructionTx::construct::<R, C>(
        call_id,
        params,
        state_id,
        &ar,
        &enclave_context,
        max_mem_size,
    )?;

    enclave_context.set_notification(ar.user_address());
    *raw_instruction_tx = instruction_tx.into_raw()?;

    Ok(())
}

pub fn inner_ecall_handshake<S: State>(
    raw_handshake_tx: &mut RawHandshakeTx,
    enclave_context: &EnclaveContext<S>,
) -> Result<()> {
    let handshake_tx = HandshakeTx::construct(&enclave_context)?;
    *raw_handshake_tx = handshake_tx.into_raw()?;

    Ok(())
}

pub fn inner_ecall_register_notification<S: State>(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge,
    enclave_context: &EnclaveContext<S>,
) -> Result<()> {
    let sig = Signature::from_bytes(&sig[..])
        .map_err(|e| anyhow!("{}", e))?;
    let pubkey = PublicKey::from_bytes(&pubkey[..])
        .map_err(|e| anyhow!("{}", e))?;
    let user_address = UserAddress::from_sig(&challenge[..], &sig, &pubkey)
        .map_err(|e| anyhow!("{}", e))?;

    enclave_context.set_notification(user_address);

    Ok(())
}
