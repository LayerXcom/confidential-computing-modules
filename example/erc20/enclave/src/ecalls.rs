use crate::state_transition::{Runtime, MAX_MEM_SIZE};
use crate::ENCLAVE_CONTEXT;
use anonify_ecall_types::cmd::*;
use anonify_enclave::{context::AnonifyEnclaveContext, workflow::*};
use anyhow::anyhow;
use frame_common::crypto::Ed25519ChallengeResponse;
use frame_enclave::{register_ecall, EnclaveEngine};
use std::{ptr, vec::Vec};

#[cfg(not(feature = "backup-enable"))]
register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<AnonifyEnclaveContext>,
    AnonifyEnclaveContext,
    (
        SEND_COMMAND_TREEKEM_CMD,
        CommandByTreeKemSender<Ed25519ChallengeResponse>
    ),
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    (
        FETCH_CIPHERTEXT_TREEKEM_CMD,
        CommandByTreeKemReceiver<Ed25519ChallengeResponse>
    ),
    // Fetch handshake received from blockchain nodes into enclave.
    (FETCH_HANDSHAKE_TREEKEM_CMD, HandshakeReceiver),
    // Get current state of the user represented the given public key from enclave memory database.
    (GET_STATE_CMD, GetState<Ed25519ChallengeResponse>),
    (JOIN_GROUP_TREEKEM_CMD, JoinGroupWithTreeKem),
    (SEND_HANDSHAKE_TREEKEM_CMD, HandshakeSender),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<Ed25519ChallengeResponse>
    ),
    (GET_ENCLAVE_ENCRYPTION_KEY_CMD, EncryptionKeyGetter),
    (SEND_REGISTER_REPORT_CMD, ReportRegistration),
    (
        GET_USER_COUNTER_CMD,
        GetUserCounter<Ed25519ChallengeResponse>
    ),
    (
        SEND_COMMAND_ENCLAVE_KEY_CMD,
        CommandByEnclaveKeySender<Ed25519ChallengeResponse>
    ),
    (
        FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD,
        CommandByEnclaveKeyReceiver<Ed25519ChallengeResponse>
    ),
);

#[cfg(feature = "backup-enable")]
register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<AnonifyEnclaveContext>,
    AnonifyEnclaveContext,
    (
        SEND_COMMAND_TREEKEM_CMD,
        CommandByTreeKemSender<Ed25519ChallengeResponse>
    ),
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    (
        FETCH_CIPHERTEXT_TREEKEM_CMD,
        CommandByTreeKemReceiver<Ed25519ChallengeResponse>
    ),
    // Fetch handshake received from blockchain nodes into enclave.
    (FETCH_HANDSHAKE_TREEKEM_CMD, HandshakeReceiver),
    // Get current state of the user represented the given public key from enclave memory database.
    (GET_STATE_CMD, GetState<Ed25519ChallengeResponse>),
    (JOIN_GROUP_TREEKEM_CMD, JoinGroupWithTreeKem),
    (SEND_HANDSHAKE_TREEKEM_CMD, HandshakeSender),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<Ed25519ChallengeResponse>
    ),
    (GET_ENCLAVE_ENCRYPTION_KEY_CMD, EncryptionKeyGetter),
    (SEND_REGISTER_REPORT_CMD, ReportRegistration),
    (BACKUP_PATH_SECRET_ALL_CMD, PathSecretBackupper),
    (RECOVER_PATH_SECRET_ALL_CMD, PathSecretRecoverer),
    (
        GET_USER_COUNTER_CMD,
        GetUserCounter<Ed25519ChallengeResponse>
    ),
);
