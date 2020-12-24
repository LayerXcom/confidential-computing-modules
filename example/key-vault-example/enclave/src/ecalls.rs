use crate::ENCLAVE_CONTEXT;
use anonify_config::constants::*;
use anonify_enclave::{context::EnclaveContext, workflow::*};
use anyhow::anyhow;
use codec::{Decode, Encode};
use frame_common::traits::{EcallInput, EcallOutput};
use frame_enclave::{register_ecall, EnclaveEngine};
use key_vault_enclave::workflow::*;
use key_vault_example_state_transition::{Runtime, MAX_MEM_SIZE};
use std::{ptr, vec::Vec};

register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<EnclaveContext>,
    EnclaveContext,
    (ENCRYPT_COMMAND_CMD, MsgSender<Ed25519ChallengeResponse>),
    // Insert a ciphertext in event logs from blockchain nodes into enclave's memory database.
    (INSERT_CIPHERTEXT_CMD, MsgReceiver),
    // Insert handshake received from blockchain nodes into enclave.
    (INSERT_HANDSHAKE_CMD, HandshakeReceiver),
    (GET_STATE_CMD, GetState<Ed25519ChallengeResponse>),
    (CALL_JOIN_GROUP_CMD, JoinGroupSender),
    (CALL_HANDSHAKE_CMD, HandshakeSender),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<Ed25519ChallengeResponse>
    ),
    (GET_ENCRYPTING_KEY_CMD, EncryptingKeyGetter),
    (START_SERVER_CMD, ServerStarter),
    (STOP_SERVER_CMD, ServerStopper),
);
