use crate::traits::State;
use crate::localstd::vec::Vec;
use codec::{Encode, Decode};

pub mod input {
    use super::*;

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct EncryptInstructionExec<ST: State> {
        state: ST,
        state_id: u64,
        call_id: u32,
    }

    impl<ST: State> EncryptInstructionExec<ST> {
        pub fn new(state: ST, state_id: u64, call_id: u32) -> Self {
            EncryptInstructionExec {
                state, state_id, call_id,
            }
        }
    }
}

pub mod output {
    use super::*;
    use crate::crypto::Ciphertext;

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct InstructionTx {
        state_id: u64,
        ciphertext: Vec<u8>,
        enclave_sig: Vec<u8>,
        msg: Vec<u8>,
    }

    impl InstructionTx {
        pub fn get_ciphertext(&mut self, len: usize) -> Ciphertext {
            Ciphertext::from_bytes(&mut self.ciphertext, len)
        }

        pub fn state_id(&self) -> u64 {
            self.state_id
        }

        pub fn ciphertext(&self) -> &[u8] {
            &self.ciphertext
        }

        pub fn enclave_sig(&self) -> &[u8] {
            &self.enclave_sig
        }

        pub fn msg(&self) -> &[u8] {
            &self.msg
        }
    }
}
