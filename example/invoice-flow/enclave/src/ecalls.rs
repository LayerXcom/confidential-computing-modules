use crate::ENCLAVE_CONTEXT;
use anonify_enclave::{context::EnclaveContext, workflow::*};
use anyhow::anyhow;
use codec::{Decode, Encode};
use config::constants::*;
use frame_common::{
    crypto::Ed25519ChallengeResponse,
    traits::{EcallInput, EcallOutput},
};
use frame_enclave::{register_ecall, EnclaveEngine};
use invoice_state_transition::{Runtime, MAX_MEM_SIZE};
use std::{ptr, vec::Vec};

register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<EnclaveContext>,
    EnclaveContext,
    (
        ENCRYPT_INSTRUCTION_CMD,
        Instruction<Ed25519ChallengeResponse>
    ),
    // Insert a ciphertext in event logs from blockchain nodes into enclave's memory database.
    (INSERT_CIPHERTEXT_CMD, InsertCiphertext),
    // Insert handshake received from blockchain nodes into enclave.
    (INSERT_HANDSHAKE_CMD, InsertHandshake),
    // Get current state of the user represented the given public key from enclave memory database.
    (GET_STATE_CMD, GetState<Ed25519ChallengeResponse>),
    (CALL_JOIN_GROUP_CMD, CallJoinGroup),
    (CALL_HANDSHAKE_CMD, CallHandshake),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<Ed25519ChallengeResponse>
    ),
);
