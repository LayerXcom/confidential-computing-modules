use crate::localstd::{
    vec::Vec,
    string::String,
    str,
};
use codec::{Encode, Decode, Input, self};
use frame_common::{
    EcallInput, EcallOutput, State,
    crypto::{Sha256, Ciphertext, ExportPathSecret},
    state_types::{StateType, MemId, UpdatedState},
    traits::AccessPolicy,
};

pub mod input {
    use super::*;

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct Instruction<AP: AccessPolicy> {
        pub access_policy: AP,
        pub state: StateType,
        pub call_id: u32,
    }

    impl<AP: AccessPolicy> EcallInput for Instruction<AP> {}

    impl<AP: AccessPolicy> Instruction<AP> {
        pub fn new(access_policy: AP, state: StateType, call_id: u32) -> Self {
            Instruction {
                access_policy,
                state,
                call_id,
            }
        }

        pub fn access_policy(&self) -> &AP {
            &self.access_policy
        }
    }

    #[derive(Encode, Decode, Debug, Clone, Default)]
    pub struct CallHandshake;

    impl EcallInput for CallHandshake {}

    #[derive(Encode, Decode, Debug, Clone, Default)]
    pub struct CallJoinGroup;

    impl EcallInput for CallJoinGroup {}

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct InsertCiphertext {
        ciphertext: Ciphertext,
    }

    impl EcallInput for InsertCiphertext {}

    impl InsertCiphertext {
        pub fn new(ciphertext: Ciphertext) -> Self {
            InsertCiphertext { ciphertext }
        }

        pub fn ciphertext(&self) -> &Ciphertext {
            &self.ciphertext
        }
    }

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct InsertHandshake {
        handshake: Vec<u8>,
    }

    impl EcallInput for InsertHandshake {}

    impl InsertHandshake {
        pub fn new(handshake: Vec<u8>) -> Self {
            InsertHandshake { handshake }
        }

        pub fn handshake(&self) -> &[u8] {
            &self.handshake[..]
        }
    }

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct GetState<AP: AccessPolicy> {
        access_policy: AP,
        mem_id: MemId,
    }

    impl<AP: AccessPolicy> EcallInput for GetState<AP> {}

    impl<AP: AccessPolicy> GetState<AP> {
        pub fn new(access_policy: AP, mem_id: MemId) -> Self {
            GetState { access_policy, mem_id }
        }

        pub fn access_policy(&self) -> &AP {
            &self.access_policy
        }

        pub fn mem_id(&self) -> MemId {
            self.mem_id
        }
    }

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct RegisterNotification<AP: AccessPolicy> {
        access_policy: AP,
    }

    impl<AP: AccessPolicy> EcallInput for RegisterNotification<AP> {}

    impl<AP: AccessPolicy> RegisterNotification<AP> {
        pub fn new(access_policy: AP) -> Self {
            RegisterNotification { access_policy }
        }

        pub fn access_policy(&self) -> &AP {
            &self.access_policy
        }
    }
}

pub mod output {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Instruction {
        enclave_sig: secp256k1::Signature,
        msg: Sha256,
        ciphertext: Ciphertext,
    }

    impl EcallOutput for Instruction {}

    impl Encode for Instruction {
        fn encode(&self) -> Vec<u8> {
            let mut acc = vec![];
            acc.extend_from_slice(&self.encode_enclave_sig());
            acc.extend_from_slice(self.msg_as_bytes());
            acc.extend_from_slice(&self.encode_ciphertext());

            acc
        }
    }

    impl Decode for Instruction {
        fn decode<I: Input>(value: &mut I) -> Result<Self, codec::Error> {
            let mut enclave_sig_buf = [0u8; 64];
            let mut msg_buf = [0u8; 32];
            value.read(&mut enclave_sig_buf)?;
            value.read(&mut msg_buf)?;

            let ciphertext_len = value.remaining_len()?
                .expect("Ciphertext length should not be zero");
            let mut ciphertext_buf = vec![0u8; ciphertext_len];
            value.read(&mut ciphertext_buf)?;

            let enclave_sig = secp256k1::Signature::parse(&enclave_sig_buf);
            let msg = Sha256::new(msg_buf);
            let ciphertext = Ciphertext::decode(&mut &ciphertext_buf[..])?;

            Ok(Instruction {
                enclave_sig, msg, ciphertext,
            })
        }
    }

    impl Instruction {
        pub fn new(ciphertext: Ciphertext, enclave_sig: secp256k1::Signature, msg: Sha256) -> Self {
            Instruction {
                enclave_sig,
                msg,
                ciphertext,
            }
        }

        pub fn ciphertext(&self) -> &Ciphertext {
            &self.ciphertext
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

        pub fn msg_as_array(&self) -> [u8; 32] {
            self.msg.as_array()
        }
    }

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct ReturnUpdatedState {
        pub updated_state: Option<UpdatedState<StateType>>,
    }

    impl EcallOutput for ReturnUpdatedState {}

    impl Default for ReturnUpdatedState {
        fn default() -> Self {
            ReturnUpdatedState {
                updated_state: None,
            }
        }
    }

    impl ReturnUpdatedState {
        pub fn new(updated_state: Option<UpdatedState<StateType>>) -> Self {
            ReturnUpdatedState { updated_state }
        }

        pub fn update(&mut self, updated_state: UpdatedState<StateType>) {
            self.updated_state = Some(updated_state)
        }
    }

    #[derive(Encode, Decode, Debug, Clone, Default)]
    pub struct Empty;

    impl EcallOutput for Empty {}

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct ReturnState {
        state: StateType,
    }

    impl EcallOutput for ReturnState {}

    impl ReturnState {
        pub fn new(state: StateType) -> Self {
            ReturnState { state }
        }

        pub fn into_vec(self) -> Vec<u8> {
            self.state.into_vec()
        }

        pub fn as_mut_bytes(&mut self) -> &mut [u8] {
            self.state.as_mut_bytes()
        }
    }

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct ReturnJoinGroup {
        report: Vec<u8>,
        report_sig: Vec<u8>,
        handshake: Vec<u8>,
        export_path_secret: ExportPathSecret,
    }

    impl EcallOutput for ReturnJoinGroup {}

    impl ReturnJoinGroup {
        pub fn new(report: Vec<u8>, report_sig: Vec<u8>, handshake: Vec<u8>, export_path_secret: ExportPathSecret) -> Self {
            ReturnJoinGroup {
                report, report_sig, handshake, export_path_secret,
            }
        }

        pub fn report(&self) -> &[u8] {
            &self.report[..]
        }

        pub fn report_sig(&self) -> &[u8] {
            &self.report_sig[..]
        }

        pub fn handshake(&self) -> &[u8] {
            &self.handshake[..]
        }

        pub fn export_path_secret_as_ref(&self) -> &ExportPathSecret {
            &self.export_path_secret
        }

        pub fn export_path_secret(self) -> ExportPathSecret {
            self.export_path_secret
        }
    }


    #[derive(Encode, Decode, Debug, Clone)]
    pub struct ReturnHandshake {
        handshake: Vec<u8>,
        export_path_secret: ExportPathSecret,
    }

    impl EcallOutput for ReturnHandshake {}

    impl ReturnHandshake {
        pub fn new(handshake: Vec<u8>, export_path_secret: ExportPathSecret) -> Self {
            ReturnHandshake { handshake, export_path_secret }
        }

        pub fn handshake(&self) -> &[u8] {
            &self.handshake[..]
        }

        pub fn export_path_secret_as_ref(&self) -> &ExportPathSecret {
            &self.export_path_secret
        }

        pub fn export_path_secret(self) -> ExportPathSecret {
            self.export_path_secret
        }
    }
}
