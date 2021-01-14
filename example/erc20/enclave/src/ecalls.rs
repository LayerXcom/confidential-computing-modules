use crate::ENCLAVE_CONTEXT;
use anonify_enclave::{context::AnonifyEnclaveContext, workflow::*};
use anyhow::anyhow;
use codec::{Decode, Encode};
use erc20_state_transition::{cmd::*, Runtime, MAX_MEM_SIZE};
use frame_common::{
    crypto::Ed25519ChallengeResponse,
    traits::{EcallInput, EcallOutput},
};
use frame_enclave::{register_ecall, EnclaveEngine};
use std::{ptr, vec::Vec};

register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<AnonifyEnclaveContext>,
    AnonifyEnclaveContext,
    (SEND_COMMAND_CMD, MsgSender<Ed25519ChallengeResponse>),
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    (FETCH_CIPHERTEXT_CMD, MsgReceiver),
    // Fetch handshake received from blockchain nodes into enclave.
    (FETCH_HANDSHAKE_CMD, HandshakeReceiver),
    // Get current state of the user represented the given public key from enclave memory database.
    (GET_STATE_CMD, GetState<Ed25519ChallengeResponse>),
    (JOIN_GROUP_CMD, JoinGroupSender),
    (SEND_HANDSHAKE_CMD, HandshakeSender),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<Ed25519ChallengeResponse>
    ),
    (GET_ENCRYPTING_KEY_CMD, EncryptingKeyGetter),
    (SEND_REGISTER_REPORT_CMD, ReportRegistration),
);
