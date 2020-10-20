use crate::ENCLAVE_CONTEXT;
use anonify_enclave::{context::EnclaveContext, workflow::*};
use anyhow::anyhow;
use codec::{Decode, Encode};
use config::constants::*;
use erc20_state_transition::{Runtime, MAX_MEM_SIZE};
use frame_common::{
    crypto::Ed25519ChallengeResponse,
    traits::{EcallInput, EcallOutput},
};
use frame_enclave::{register_ecall, EnclaveEngine};
use std::{ptr, vec::Vec};

register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<EnclaveContext>,
    EnclaveContext,
    (ENCRYPT_INSTRUCTION_CMD, MsgSender<Ed25519ChallengeResponse>),
    // Insert a ciphertext in event logs from blockchain nodes into enclave's memory database.
    (INSERT_CIPHERTEXT_CMD, MsgReceiver),
    // Insert handshake received from blockchain nodes into enclave.
    (INSERT_HANDSHAKE_CMD, HandshakeReceiver),
    // Get current state of the user represented the given public key from enclave memory database.
    (GET_STATE_CMD, GetState<Ed25519ChallengeResponse>),
    (CALL_JOIN_GROUP_CMD, JoinGroupSender),
    (CALL_HANDSHAKE_CMD, HandshakeSender),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<Ed25519ChallengeResponse>
    ),
);
