use crate::state_transition::Runtime;
use crate::ENCLAVE_CONTEXT;
use anonify_enclave::{context::AnonifyEnclaveContext, workflow::*};
use frame_common::crypto::NoAuth;
use frame_enclave::{register_enclave_use_case, StateRuntimeEnclaveUseCase};

register_enclave_use_case!(
    &*ENCLAVE_CONTEXT,
    #[cfg(feature = "enclave_key")]
    CommandByEnclaveKeySender<AnonifyEnclaveContext, Runtime<AnonifyEnclaveContext>,NoAuth>,
    #[cfg(feature = "treekem")]
    CommandByTreeKemSender<AnonifyEnclaveContext, Runtime<AnonifyEnclaveContext>,NoAuth>,
    #[cfg(feature = "enclave_key")]
    CommandByEnclaveKeyReceiver<AnonifyEnclaveContext, Runtime<AnonifyEnclaveContext>,NoAuth>,
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    #[cfg(feature = "treekem")]
    CommandByTreeKemReceiver<AnonifyEnclaveContext, Runtime<AnonifyEnclaveContext>,  NoAuth>,
    #[cfg(feature = "treekem")]
    HandshakeSender<AnonifyEnclaveContext>,
    // Fetch handshake received from blockchain nodes into enclave.
    #[cfg(feature = "treekem")]
    HandshakeReceiver<AnonifyEnclaveContext>,
    // Get current state of the user represented the given public key from enclave memory database.
    #[cfg(feature = "enclave_key")]
    JoinGroupWithEnclaveKey<AnonifyEnclaveContext>,
    #[cfg(feature = "treekem")]
    JoinGroupWithTreeKem<AnonifyEnclaveContext>,
    GetState<AnonifyEnclaveContext,Runtime<AnonifyEnclaveContext>,NoAuth>,
    RegisterNotification<AnonifyEnclaveContext,NoAuth>,
    EncryptionKeyGetter<AnonifyEnclaveContext>,
    ReportRegistration<AnonifyEnclaveContext>,
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    PathSecretsBackupper<AnonifyEnclaveContext>,
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    PathSecretsRecoverer<AnonifyEnclaveContext>,
    GetUserCounter<AnonifyEnclaveContext,NoAuth>,
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    EnclaveKeyBackupper<AnonifyEnclaveContext>,
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    EnclaveKeyRecoverer<AnonifyEnclaveContext>,
);
