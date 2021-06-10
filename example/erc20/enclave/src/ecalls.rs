use crate::state_transition::Runtime;
use crate::{ENCLAVE_CONTEXT, ENCLAVE_CONTEXT_WITH_CMD_CIPHER_PADDING_SIZE};
use anonify_enclave::{context::AnonifyEnclaveContext, use_case::*};
use frame_common::crypto::NoAuth;
use frame_enclave::{register_enclave_use_case, StateRuntimeEnclaveUseCase};

register_enclave_use_case!(
    #[cfg(feature = "enclave_key")]
    (CommandByEnclaveKeySender<Runtime<AnonifyEnclaveContext>,NoAuth>, &*ENCLAVE_CONTEXT_WITH_CMD_CIPHER_PADDING_SIZE),
    #[cfg(feature = "treekem")]
    (CommandByTreeKemSender<Runtime<AnonifyEnclaveContext>,NoAuth>, &*ENCLAVE_CONTEXT_WITH_CMD_CIPHER_PADDING_SIZE),
    #[cfg(feature = "enclave_key")]
    (CommandByEnclaveKeyReceiver<Runtime<AnonifyEnclaveContext>,NoAuth>, &*ENCLAVE_CONTEXT),
    // Fetch a ciphertext in event logs from blockchain nodes into enclave's memory database.
    #[cfg(feature = "treekem")]
    (CommandByTreeKemReceiver<Runtime<AnonifyEnclaveContext>,  NoAuth>, &*ENCLAVE_CONTEXT),
    #[cfg(feature = "treekem")]
    (HandshakeSender, &*ENCLAVE_CONTEXT),
    // Fetch handshake received from blockchain nodes into enclave.
    #[cfg(feature = "treekem")]
    (HandshakeReceiver, &*ENCLAVE_CONTEXT),
    // Get current state of the user represented the given public key from enclave memory database.
    #[cfg(feature = "enclave_key")]
    (JoinGroupWithEnclaveKey, &*ENCLAVE_CONTEXT),
    #[cfg(feature = "treekem")]
    (JoinGroupWithTreeKem, &*ENCLAVE_CONTEXT),
    (GetState<Runtime<AnonifyEnclaveContext>,NoAuth>, &*ENCLAVE_CONTEXT),
    (RegisterNotification<NoAuth>, &*ENCLAVE_CONTEXT),
    (EncryptionKeyGetter, &*ENCLAVE_CONTEXT),
    (ReportRegistration, &*ENCLAVE_CONTEXT),
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    (PathSecretsBackupper, &*ENCLAVE_CONTEXT),
    #[cfg(feature = "treekem")]
    #[cfg(feature = "backup-enable")]
    (PathSecretsRecoverer, &*ENCLAVE_CONTEXT),
    (GetUserCounter<NoAuth>, &*ENCLAVE_CONTEXT),
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    (EnclaveKeyBackupper, &*ENCLAVE_CONTEXT),
    #[cfg(feature = "enclave_key")]
    #[cfg(feature = "backup-enable")]
    (EnclaveKeyRecoverer, &*ENCLAVE_CONTEXT),
);
