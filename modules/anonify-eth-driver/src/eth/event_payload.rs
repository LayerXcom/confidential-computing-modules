use super::{
    connection::{Web3Contract, Web3Http},
    event_def::*,
};
use crate::{
    cache::EventCache,
    error::{HostError, Result},
    utils::*,
    workflow::*,
};
use anonify_ecall_types::{CommandCiphertext, EnclaveKeyCiphertext};
use ethabi::ParamType;
use frame_common::{crypto::ExportHandshake, state_types::StateCounter, TreeKemCiphertext};
use frame_host::engine::HostEngine;
use sgx_types::sgx_enclave_id_t;
use std::{cmp::Ordering, fmt};
use tracing::{debug, error, info, warn};
use web3::types::{Address, Log};

#[derive(Debug, Clone)]
pub(crate) struct PayloadType {
    pub(crate) payload: Payload,
    pub(crate) state_counter: StateCounter,
}

impl PayloadType {
    // /// other is the next of self
    // pub(crate) fn is_next(&self, other: &Self) -> bool {
    //     self.roster_idx == other.roster_idx
    //         && ((self.epoch == other.epoch && self.generation + 1 == other.generation) ||
    //         (self.epoch == other.epoch && other.generation == u32::MAX) || // TODO: order gurantee with handshake
    //         (self.epoch + 1 == other.epoch && self.generation == u32::MAX && other.generation == 0))
    // }

    pub(crate) fn payload(&self) -> &Payload {
        &self.payload
    }

    pub(crate) fn state_counter(&self) -> StateCounter {
        self.state_counter
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Payload {
    TreeKemCiphertext {
        roster_idx: u32,
        epoch: u32,
        generation: u32,
        ciphertext: TreeKemCiphertext,
    },
    EnclaveKeyCiphertext(EnclaveKeyCiphertext),
    Handshake {
        roster_idx: u32,
        epoch: u32,
        generation: u32,
        handshake: ExportHandshake,
    },
}

impl Default for Payload {
    fn default() -> Self {
        Payload::EnclaveKeyCiphertext(EnclaveKeyCiphertext::default())
    }
}
