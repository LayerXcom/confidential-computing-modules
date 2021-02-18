use crate::state_transition::{Runtime, MAX_MEM_SIZE};
use crate::ENCLAVE_CONTEXT;
use anonify_ecall_types::cmd::*;
use anonify_enclave::{context::AnonifyEnclaveContext, workflow::*};
use anyhow::anyhow;
use frame_common::crypto::NoAuth;
use frame_enclave::{register_ecall, EnclaveEngine};
use std::{ptr, vec::Vec};

#[cfg(not(feature = "backup-enable"))]
register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<AnonifyEnclaveContext>,
    AnonifyEnclaveContext,
    (SEND_COMMAND_CMD, CmdSender<NoAuth>),
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    (FETCH_CIPHERTEXT_CMD, CmdReceiver<NoAuth>),
    // Fetch handshake received from blockchain nodes into enclave.
    (FETCH_HANDSHAKE_CMD, HandshakeReceiver),
    // Get current state of the user represented the given public key from enclave memory database.
    (GET_STATE_CMD, GetState<NoAuth>),
    (JOIN_GROUP_CMD, JoinGroupSender),
    (SEND_HANDSHAKE_CMD, HandshakeSender),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<NoAuth>
    ),
    (GET_ENCLAVE_ENCRYPTION_KEY_CMD, EncryptionKeyGetter),
    (SEND_REGISTER_REPORT_CMD, ReportRegistration),
);

#[cfg(feature = "backup-enable")]
register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<AnonifyEnclaveContext>,
    AnonifyEnclaveContext,
    (SEND_COMMAND_CMD, CmdSender<NoAuth>),
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    (FETCH_CIPHERTEXT_CMD, CmdReceiver<NoAuth>),
    // Fetch handshake received from blockchain nodes into enclave.
    (FETCH_HANDSHAKE_CMD, HandshakeReceiver),
    // Get current state of the user represented the given public key from enclave memory database.
    (GET_STATE_CMD, GetState<NoAuth>),
    (JOIN_GROUP_CMD, JoinGroupSender),
    (SEND_HANDSHAKE_CMD, HandshakeSender),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<NoAuth>
    ),
    (GET_ENCLAVE_ENCRYPTION_KEY_CMD, EncryptionKeyGetter),
    (SEND_REGISTER_REPORT_CMD, ReportRegistration),
    (BACKUP_PATH_SECRET_ALL_CMD, PathSecretBackupper),
    (RECOVER_PATH_SECRET_ALL_CMD, PathSecretRecoverer),
);
