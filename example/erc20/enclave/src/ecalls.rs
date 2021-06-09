use crate::state_transition::Runtime;
use crate::ENCLAVE_CONTEXT;
use anonify_enclave::{context::AnonifyEnclaveContext, use_case::*};
use frame_common::crypto::NoAuth;
use frame_enclave::{register_enclave_use_case, StateRuntimeEnclaveUseCase};

register_enclave_use_case!(
    &*ENCLAVE_CONTEXT,
    #[cfg(feature = "enclave_key")]
    CommandByEnclaveKeySender<Runtime<AnonifyEnclaveContext>,NoAuth>,
    #[cfg(feature = "treekem")]
    CommandByTreeKemSender<Runtime<AnonifyEnclaveContext>,NoAuth>,
    #[cfg(feature = "enclave_key")]
    CommandByEnclaveKeyReceiver<Runtime<AnonifyEnclaveContext>,NoAuth>,
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    #[cfg(feature = "treekem")]
    CommandByTreeKemReceiver<Runtime<AnonifyEnclaveContext>,  NoAuth>,
    #[cfg(feature = "treekem")]
    HandshakeSender,
    // Fetch handshake received from blockchain nodes into enclave.
    #[cfg(feature = "treekem")]
    HandshakeReceiver,
    // Get current state of the user represented the given public key from enclave memory database.
    #[cfg(feature = "enclave_key")]
    JoinGroupWithEnclaveKey,
    #[cfg(feature = "treekem")]
    JoinGroupWithTreeKem,
    GetState<Runtime<AnonifyEnclaveContext>,NoAuth>,
    RegisterNotification<NoAuth>,
    EncryptionKeyGetter,
    ReportRegistration,
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    PathSecretsBackupper,
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    PathSecretsRecoverer,
    GetUserCounter<NoAuth>,
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    EnclaveKeyBackupper,
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    EnclaveKeyRecoverer,
);
