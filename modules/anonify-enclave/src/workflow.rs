use std::{
    slice,
    marker::PhantomData,
};
use sgx_types::*;
use frame_types::*;
use frame_enclave::EnclaveEngine;
use anonify_io_types::*;
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

#[derive(Debug, Clone)]
pub struct Instruction;

impl EnclaveEngine for Instruction {
    type EI = input::Instruction;
    type EO = output::Instruction;

    fn handle<R, C>(
        mut ecall_input: Self::EI,
        enclave_context: &C,
        max_mem_size: usize
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let state = ecall_input.state.as_mut_bytes();
        let ar = &ecall_input.access_right;

        let instruction_output = create_instruction_output::<R, C>(
            ecall_input.call_id,
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
pub struct InsertCiphertext;

impl EnclaveEngine for InsertCiphertext {
    type EI = input::InsertCiphertext;
    type EO = output::ReturnUpdatedState;

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let group_key = &mut *enclave_context.write_group_key();
        let iter_op = Instructions::<R, C>::state_transition(enclave_context.clone(), ecall_input.ciphertext(), group_key)?;
        let mut output = output::ReturnUpdatedState::default();

        if let Some(updated_state_iter) = iter_op {
            if let Some(updated_state) = enclave_context.update_state(updated_state_iter) {
                output.update(updated_state);
            }
        }

        let roster_idx = ecall_input.ciphertext().roster_idx() as usize;
        // ratchet app keychain per a log.
        group_key.ratchet(roster_idx)?;

        Ok(output)
    }
}

#[derive(Debug, Clone)]
pub struct InsertHandshake;

impl EnclaveEngine for InsertHandshake {
    type EI = input::InsertHandshake;
    type EO = output::Empty;

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let group_key = &mut *enclave_context.write_group_key();
        let handshake = HandshakeParams::decode(&mut ecall_input.handshake())
            .map_err(|_| anyhow!("HandshakeParams::decode Error"))?;

        group_key.process_handshake(&handshake)?;

        Ok(output::Empty::default())
    }
}

#[derive(Debug, Clone)]
pub struct GetState;

impl EnclaveEngine for GetState {
    type EI = input::GetState;
    type EO = output::ReturnState;

    fn eval_policy<R, C>(ecall_input: &Self::EI) -> anyhow::Result<()>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        unimplemented!();
    }

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let addr = ecall_input.access_right().verified_user_address()?;
        let user_state = enclave_context.get_state(addr, ecall_input.mem_id());

        Ok(output::ReturnState::new(user_state))
    }
}

#[derive(Debug, Clone)]
pub struct CallJoinGroup;

impl EnclaveEngine for CallJoinGroup {
    type EI = input::CallJoinGroup;
    type EO = output::ReturnJoinGroup;

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::EO>
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

#[derive(Debug, Clone)]
pub struct CallHandshake;

impl EnclaveEngine for CallHandshake {
    type EI = input::CallHandshake;
    type EO = output::ReturnHandshake;

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let group_key = &*enclave_context.read_group_key();
        let handshake = group_key.create_handshake()?;

        Ok(output::ReturnHandshake::new(handshake.encode()))
    }
}

#[derive(Debug, Clone)]
pub struct RegisterNotification;

impl EnclaveEngine for RegisterNotification {
    type EI = input::RegisterNotification;
    type EO = output::Empty;

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize
    ) -> Result<Self::EO>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone,
    {
        let addr = ecall_input.access_right().verified_user_address()?;
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
