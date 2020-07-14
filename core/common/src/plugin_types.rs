use crate::traits::State;
use crate::localstd::vec::Vec;
use crate::crypto::{AccessRight, Sha256};
use codec::{Encode, Decode, Input, self};
use crate::state_types::StateType;

pub trait EcallInput {}
pub trait EcallOutput {}

pub mod input {
    use super::*;

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct Instruction {
        pub access_right: AccessRight,
        pub state: StateType,
        pub state_id: u64,
        pub call_id: u32,
    }

    impl EcallInput for Instruction {}

    impl Instruction {
        pub fn new(access_right: AccessRight, state: StateType, state_id: u64, call_id: u32) -> Self {
            Instruction {
                access_right,
                state,
                state_id,
                call_id,
            }
        }
    }
}

pub mod output {
    use super::*;
    use crate::crypto::Ciphertext;

    #[derive(Debug, Clone)]
    pub struct Instruction {
        state_id: u64,
        enclave_sig: secp256k1::Signature,
        msg: Sha256,
        ciphertext: Ciphertext,
    }

    impl EcallOutput for Instruction {}

    impl Encode for Instruction {
        fn encode(&self) -> Vec<u8> {
            let mut acc = vec![];
            acc.extend_from_slice(&self.state_id.encode());
            acc.extend_from_slice(&self.encode_enclave_sig());
            acc.extend_from_slice(self.msg_as_bytes());
            acc.extend_from_slice(&self.encode_ciphertext());

            acc
        }
    }

    impl Decode for Instruction {
        fn decode<I: Input>(value: &mut I) -> Result<Self, codec::Error> {
            let mut state_id_buf = [0u8; 8];
            let mut enclave_sig_buf = [0u8; 64];
            let mut msg_buf = [0u8; 32];

            value.read(&mut state_id_buf)?;
            value.read(&mut enclave_sig_buf)?;
            value.read(&mut msg_buf)?;

            let ciphertext_len = value.remaining_len()?
                .expect("Ciphertext length should not be zero");
            let mut ciphertext_buf = vec![0u8; ciphertext_len];
            value.read(&mut ciphertext_buf)?;

            let state_id = u64::decode(&mut &state_id_buf[..])?;
            let enclave_sig = secp256k1::Signature::parse(&enclave_sig_buf);
            let msg = Sha256::new(msg_buf);
            let ciphertext = Ciphertext::decode(&mut &ciphertext_buf[..])?;

            Ok(Instruction {
                state_id, enclave_sig, msg, ciphertext,
            })
        }
    }

    impl Instruction {
        pub fn new(state_id: u64, ciphertext: Ciphertext, enclave_sig: secp256k1::Signature, msg: Sha256) -> Self {
            Instruction {
                state_id,
                enclave_sig,
                msg,
                ciphertext,
            }
        }

        pub fn ciphertext(&self) -> &Ciphertext {
            &self.ciphertext
        }

        pub fn state_id(&self) -> u64 {
            self.state_id
        }

        pub fn encode_ciphertext(&self) -> Vec<u8> {
            self.ciphertext.encode()
        }

        pub fn encode_enclave_sig(&self) -> [u8; 64] {
            self.enclave_sig.serialize()
        }

        pub fn msg_as_bytes(&self) -> &[u8] {
            &self.msg.as_bytes()
        }
    }
}
