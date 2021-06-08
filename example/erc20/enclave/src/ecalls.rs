use crate::state_transition::Runtime;
use crate::ENCLAVE_CONTEXT;
use anonify_ecall_types::cmd::*;
use anonify_enclave::{context::AnonifyEnclaveContext, workflow::*};
use frame_common::crypto::NoAuth;
use frame_enclave::{register_enclave_use_case, StateRuntimeEnclaveUseCase};

register_enclave_use_case!(
    &*ENCLAVE_CONTEXT,
    MAX_MEM_SIZE,
    Runtime<AnonifyEnclaveContext>,
    AnonifyEnclaveContext,
    #[cfg(feature = "enclave_key")]
    (
        SEND_COMMAND_ENCLAVE_KEY_CMD,
        CommandByEnclaveKeySender<AnonifyEnclaveContext, Runtime<AnonifyEnclaveContext>,NoAuth>
    ),
    #[cfg(feature = "treekem")]
    (
        SEND_COMMAND_TREEKEM_CMD,
        CommandByTreeKemSender<AnonifyEnclaveContext, Runtime<AnonifyEnclaveContext>,NoAuth>
    ),
    #[cfg(feature = "enclave_key")]
    (
        FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD,
        CommandByEnclaveKeyReceiver<AnonifyEnclaveContext, Runtime<AnonifyEnclaveContext>,NoAuth>
    ),
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    #[cfg(feature = "treekem")]
    (
        FETCH_CIPHERTEXT_TREEKEM_CMD,
        CommandByTreeKemReceiver<AnonifyEnclaveContext, Runtime<AnonifyEnclaveContext>,  NoAuth>
    ),
    #[cfg(feature = "treekem")]
    (SEND_HANDSHAKE_TREEKEM_CMD, HandshakeSender<AnonifyEnclaveContext>),
    // Fetch handshake received from blockchain nodes into enclave.
    #[cfg(feature = "treekem")]
    (FETCH_HANDSHAKE_TREEKEM_CMD, HandshakeReceiver<AnonifyEnclaveContext>),
    // Get current state of the user represented the given public key from enclave memory database.
    #[cfg(feature = "enclave_key")]
    (JOIN_GROUP_ENCLAVE_KEY_CMD, JoinGroupWithEnclaveKey<AnonifyEnclaveContext>),
    #[cfg(feature = "treekem")]
    (JOIN_GROUP_TREEKEM_CMD, JoinGroupWithTreeKem<AnonifyEnclaveContext>),
    (GET_STATE_CMD, GetState<AnonifyEnclaveContext,Runtime<AnonifyEnclaveContext>,NoAuth>),
    (
        REGISTER_NOTIFICATION_CMD,
        RegisterNotification<AnonifyEnclaveContext,NoAuth>
    ),
    (GET_ENCLAVE_ENCRYPTION_KEY_CMD, EncryptionKeyGetter<AnonifyEnclaveContext>),
    (SEND_REGISTER_REPORT_CMD, ReportRegistration<AnonifyEnclaveContext>),
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    (BACKUP_PATH_SECRETS_CMD, PathSecretsBackupper<AnonifyEnclaveContext>),
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    (RECOVER_PATH_SECRETS_CMD, PathSecretsRecoverer<AnonifyEnclaveContext>),
    (
        GET_USER_COUNTER_CMD,
        GetUserCounter<AnonifyEnclaveContext,NoAuth>
    ),
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    (BACKUP_ENCLAVE_KEY_CMD, EnclaveKeyBackupper<AnonifyEnclaveContext>),
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    (RECOVER_ENCLAVE_KEY_CMD, EnclaveKeyRecoverer<AnonifyEnclaveContext>),
);
