use anonify_ecall_types::EnclaveKeyCiphertext;
use frame_common::{crypto::ExportHandshake, state_types::StateCounter, TreeKemCiphertext};

#[derive(Debug, Clone)]
pub(crate) struct PayloadType {
    pub(crate) payload: Payload,
    pub(crate) state_counter: StateCounter,
}

impl PayloadType {
    pub(crate) fn state_counter(&self) -> StateCounter {
        self.state_counter
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Payload {
    TreeKemCiphertext {
        roster_idx: u32,
        epoch: u32,
        generation: u32,
        ciphertext: TreeKemCiphertext,
    },
    EnclaveKeyCiphertext(EnclaveKeyCiphertext),
    Handshake {
        roster_idx: u32,
        epoch: u32,
        generation: u32,
        handshake: ExportHandshake,
    },
}

impl Default for Payload {
    fn default() -> Self {
        Payload::EnclaveKeyCiphertext(EnclaveKeyCiphertext::default())
    }
}
