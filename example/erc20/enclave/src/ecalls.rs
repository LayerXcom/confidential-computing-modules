use crate::state_transition::{Runtime, MAX_MEM_SIZE};
use crate::ENCLAVE_CONTEXT;
use anonify_ecall_types::cmd::*;
use anonify_enclave::{context::AnonifyEnclaveContext, workflow::*};
use anyhow::anyhow;
use frame_common::crypto::NoAuth;
use frame_enclave::{register_ecall, StateRuntimeEnclaveEngine};
use std::{ptr, vec::Vec};

register_ecall!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<AnonifyEnclaveContext>,
    AnonifyEnclaveContext,
    #[cfg(feature = "enclave_key")]
    (
        SEND_COMMAND_ENCLAVE_KEY_CMD,
        CommandByEnclaveKeySender<NoAuth>
    ),
    #[cfg(feature = "treekem")]
    (
        SEND_COMMAND_TREEKEM_CMD,
        CommandByTreeKemSender<NoAuth>
    ),
    #[cfg(feature = "enclave_key")]
    (
        FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD,
        CommandByEnclaveKeyReceiver<NoAuth>
    ),
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    #[cfg(feature = "treekem")]
    (
        FETCH_CIPHERTEXT_TREEKEM_CMD,
        CommandByTreeKemReceiver<NoAuth>
    ),
    #[cfg(feature = "treekem")]
    (SEND_HANDSHAKE_TREEKEM_CMD, HandshakeSender),
    // Fetch handshake received from blockchain nodes into enclave.
    #[cfg(feature = "treekem")]
    (FETCH_HANDSHAKE_TREEKEM_CMD, HandshakeReceiver),
    // Get current state of the user represented the given public key from enclave memory database.
    #[cfg(feature = "enclave_key")]
    (JOIN_GROUP_ENCLAVE_KEY_CMD, JoinGroupWithEnclaveKey),
    #[cfg(feature = "treekem")]
    (JOIN_GROUP_TREEKEM_CMD, JoinGroupWithTreeKem),
    (GET_STATE_CMD, GetState<NoAuth>),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<NoAuth>
    ),
    (GET_ENCLAVE_ENCRYPTION_KEY_CMD, EncryptionKeyGetter),
    (SEND_REGISTER_REPORT_CMD, ReportRegistration),
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    (BACKUP_PATH_SECRET_ALL_CMD, PathSecretBackupper),
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    (RECOVER_PATH_SECRET_ALL_CMD, PathSecretRecoverer),
    (
        GET_USER_COUNTER_CMD,
        GetUserCounter<NoAuth>
    ),
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    (BACKUP_ENCLAVE_KEY_CMD, EnclaveKeyBackupper),
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    (RECOVER_ENCLAVE_KEY_CMD, EnclaveKeyRecoverer),
);
