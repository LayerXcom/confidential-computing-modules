use std::{
    slice,
    marker::PhantomData,
};
use sgx_types::*;
use frame_types::*;
use frame_enclave::EcallHandler;
use anonify_common::plugin_types::*;
use frame_common::{
    crypto::{UserAddress, AccessRight, Ciphertext, Sha256},
    traits::*,
    state_types::{MemId, StateType},
};
use frame_runtime::traits::*;
use frame_treekem::handshake::HandshakeParams;
use ed25519_dalek::{PublicKey, Signature};
use codec::{Decode, Encode};
use remote_attestation::RAService;
use log::debug;
use anyhow::{Result, anyhow};
use crate::{
    instructions::Instructions,
    context::EnclaveContext,
    config::{IAS_URL, TEST_SUB_KEY},
};

#[derive(Encode, Decode, Debug, Clone)]
pub struct Instruction {
    inner: input::Instruction,
}

impl From<input::Instruction> for Instruction {
    fn from(p: input::Instruction) -> Self {
        Instruction { inner: p }
    }
}

impl EcallHandler for Instruction {
    type O = output::Instruction;

    fn handle<R, C>(
        mut self,
        enclave_context: &C,
        max_mem_size: usize
    ) -> Result<Self::O>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let state = self.inner.state.as_mut_bytes();
        let ar = &self.inner.access_right;

        let instruction_output = create_instruction_output::<R, C>(
            self.inner.call_id,
            state,
            ar,
            enclave_context,
            max_mem_size,
        )?;

        let addr = ar.verified_user_address()?;
        enclave_context.set_notification(addr);

        Ok(instruction_output)
    }
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct InsertCiphertext {
    inner: input::InsertCiphertext,
}

impl From<input::InsertCiphertext> for InsertCiphertext {
    fn from(p: input::InsertCiphertext) -> Self {
        InsertCiphertext { inner: p }
    }
}

impl EcallHandler for InsertCiphertext {
    type O = output::ReturnUpdatedState;

    fn handle<R, C>(
        self,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::O>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let group_key = &mut *enclave_context.write_group_key();
        let iter_op = Instructions::<R, C>::state_transition(enclave_context.clone(), self.inner.ciphertext(), group_key)?;
        let mut output = output::ReturnUpdatedState::default();

        if let Some(updated_state_iter) = iter_op {
            if let Some(updated_state) = enclave_context.update_state(updated_state_iter) {
                output.update(updated_state);
            }
        }

        let roster_idx = self.inner.ciphertext().roster_idx() as usize;
        // ratchet app keychain per a log.
        group_key.ratchet(roster_idx)?;

        Ok(output)
    }
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct InsertHandshake {
    inner: input::InsertHandshake,
}

impl From<input::InsertHandshake> for InsertHandshake {
    fn from(p: input::InsertHandshake) -> Self {
        InsertHandshake { inner: p }
    }
}

impl EcallHandler for InsertHandshake {
    type O = output::Empty;

    fn handle<R, C>(
        self,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::O>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let group_key = &mut *enclave_context.write_group_key();
        let handshake = HandshakeParams::decode(&mut self.inner.handshake())
            .map_err(|_| anyhow!("HandshakeParams::decode Error"))?;

        group_key.process_handshake(&handshake)?;

        Ok(output::Empty::default())
    }
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct GetState {
    inner: input::GetState,
}

impl From<input::GetState> for GetState {
    fn from(p: input::GetState) -> Self {
        GetState { inner: p }
    }
}

impl EcallHandler for GetState {
    type O = output::ReturnState;

    fn handle<R, C>(
        self,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::O>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let addr = self.inner.access_right().verified_user_address()?;
        let user_state = enclave_context.get_state(addr, self.inner.mem_id());

        Ok(output::ReturnState::new(user_state))
    }
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct CallJoinGroup {
    inner: input::CallJoinGroup,
}

impl From<input::CallJoinGroup> for CallJoinGroup {
    fn from(p: input::CallJoinGroup) -> Self {
        CallJoinGroup { inner: p }
    }
}

impl EcallHandler for CallJoinGroup {
    type O = output::ReturnJoinGroup;

    fn handle<R, C>(
        self,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::O>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let quote = enclave_context.quote()?;
        let (report, report_sig) = RAService::remote_attestation(IAS_URL, TEST_SUB_KEY, &quote)?;
        let group_key = &*enclave_context.read_group_key();
        let handshake = group_key.create_handshake()?;

        Ok(output::ReturnJoinGroup::new(
            report.into_vec(),
            report_sig.into_vec(),
            handshake.encode(),
        ))
    }
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct CallHandshake {
    inner: input::CallHandshake,
}

impl From<input::CallHandshake> for CallHandshake {
    fn from(p: input::CallHandshake) -> Self {
        CallHandshake { inner: p }
    }
}

impl EcallHandler for CallHandshake {
    type O = output::ReturnHandshake;

    fn handle<R, C>(
        self,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::O>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let group_key = &*enclave_context.read_group_key();
        let handshake = group_key.create_handshake()?;

        Ok(output::ReturnHandshake::new(handshake.encode()))
    }
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct RegisterNotification {
    inner: input::RegisterNotification,
}

impl From<input::RegisterNotification> for RegisterNotification {
    fn from(p: input::RegisterNotification) -> Self {
        RegisterNotification { inner: p }
    }
}

impl EcallHandler for RegisterNotification {
    type O = output::Empty;

    fn handle<R, C>(
        self,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::O>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let addr = self.inner.access_right().verified_user_address()?;
        enclave_context.set_notification(addr);

        Ok(output::Empty::default())
    }
}

fn create_instruction_output<R, C>(
    call_id: u32,
    params: &mut [u8],
    access_right: &AccessRight,
    enclave_ctx: &C,
    max_mem_size: usize,
) -> Result<output::Instruction>
where
    R: RuntimeExecutor<C, S=StateType>,
    C: ContextOps,
{
    let group_key = &*enclave_ctx.read_group_key();
    let ciphertext = Instructions::<R, C>::new(call_id, params, &access_right)?
        .encrypt(group_key, max_mem_size)?;
    let msg = Sha256::hash(&ciphertext.encode());
    let enclave_sig = enclave_ctx.sign(msg.as_bytes())?;

    Ok(output::Instruction::new(
        ciphertext,
        enclave_sig,
        msg,
    ))
}
