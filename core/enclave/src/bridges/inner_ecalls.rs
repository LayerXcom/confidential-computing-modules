use std::{
    slice,
    marker::PhantomData,
};
use sgx_types::*;
use anonify_types::*;
use anonify_common::{
    crypto::{UserAddress, AccessRight, Ciphertext},
    traits::*,
    state_types::{MemId, StateType},
    plugin_types::*,
};
use anonify_runtime::traits::*;
use anonify_treekem::handshake::HandshakeParams;
use ed25519_dalek::{PublicKey, Signature};
use codec::{Decode, Encode};
use log::debug;
use anyhow::{Result, anyhow};
use crate::{
    transaction::*,
    instructions::Instructions,
    notify::updated_state_into_raw,
    bridges::ocalls::save_to_host_memory,
    context::EnclaveContext,
};

pub trait EcallHandler {
    type O: EcallOutput + Encode + Decode;

    fn handle< R: RuntimeExecutor<C, S=StateType>, C: ContextOps>(self, enclave_context: &EnclaveContext, max_mem_size: usize) -> Result<Self::O>;
}

impl EcallHandler for input::EncryptInstruction<StateType> {
    type O = output::InstructionTx;

    fn handle<R: RuntimeExecutor<C, S=StateType>, C: ContextOps>(
        self,
        enclave_context: &EnclaveContext,
        max_mem_size: usize
    ) -> Result<Self::O> {
        let state = &mut self.state.encode_s();
        let ar = &self.access_right;

        let instruction_tx = construct::<R, C>(
            self.call_id,
            state,
            self.state_id,
            ar,
            enclave_context,
            max_mem_size,
        )?;

        enclave_context.set_notification(ar.user_address());
        Ok(instruction_tx)
    }
}

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

pub fn inner_ecall_insert_handshake(
    handshake: *mut u8,
    handshake_len: usize,
    enclave_context: &EnclaveContext,
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
    enclave_context: &EnclaveContext,
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

pub fn inner_ecall_join_group(
    raw_join_group_tx: &mut RawJoinGroupTx,
    enclave_context: &EnclaveContext,
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

pub fn inner_ecall_handshake(
    raw_handshake_tx: &mut RawHandshakeTx,
    enclave_context: &EnclaveContext,
) -> Result<()> {
    let handshake_tx = HandshakeTx::construct(&enclave_context)?;
    *raw_handshake_tx = handshake_tx.into_raw()?;

    Ok(())
}

pub fn inner_ecall_register_notification(
    sig: &RawSig,
    pubkey: &RawPubkey,
    challenge: &RawChallenge,
    enclave_context: &EnclaveContext,
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
