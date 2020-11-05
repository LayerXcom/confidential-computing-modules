use crate::localstd::vec::Vec;
use codec::{self, Decode, Encode, Input};
use frame_common::{
    crypto::{Ciphertext, ExportHandshake, ExportPathSecret},
    state_types::{MemId, StateType, UpdatedState},
    traits::AccessPolicy,
    EcallInput, EcallOutput,
};
use frame_treekem::{DhPubKey, EciesCiphertext};

pub mod input {
    use super::*;

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct Command<AP: AccessPolicy> {
        pub access_policy: AP,
        pub encrypted_command: EciesCiphertext,
        pub call_id: u32,
    }

    impl<AP: AccessPolicy> EcallInput for Command<AP> {}

    impl<AP: AccessPolicy> Command<AP> {
        pub fn new(access_policy: AP, encrypted_command: EciesCiphertext, call_id: u32) -> Self {
            Command {
                access_policy,
                encrypted_command,
                call_id,
            }
        }

        pub fn access_policy(&self) -> &AP {
            &self.access_policy
        }
    }

    #[derive(Encode, Decode, Debug, Clone, Default)]
    pub struct GetEncryptingKey;

    impl EcallInput for GetEncryptingKey {}

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
        handshake: ExportHandshake,
    }

    impl EcallInput for InsertHandshake {}

    impl InsertHandshake {
        pub fn new(handshake: ExportHandshake) -> Self {
            InsertHandshake { handshake }
        }

        pub fn handshake(&self) -> &ExportHandshake {
            &self.handshake
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
            GetState {
                access_policy,
                mem_id,
            }
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
    pub struct Command {
        enclave_sig: secp256k1::Signature,
        ciphertext: Ciphertext,
    }

    impl EcallOutput for Command {}

    impl Encode for Command {
        fn encode(&self) -> Vec<u8> {
            let mut acc = vec![];
            acc.extend_from_slice(&self.encode_enclave_sig());
            acc.extend_from_slice(&self.encode_ciphertext());

            acc
        }
    }

    impl Decode for Command {
        fn decode<I: Input>(value: &mut I) -> Result<Self, codec::Error> {
            let mut enclave_sig_buf = [0u8; 64];
            value.read(&mut enclave_sig_buf)?;

            let ciphertext_len = value
                .remaining_len()?
                .expect("Ciphertext length should not be zero");
            let mut ciphertext_buf = vec![0u8; ciphertext_len];
            value.read(&mut ciphertext_buf)?;

            let enclave_sig = secp256k1::Signature::parse(&enclave_sig_buf);
            let ciphertext = Ciphertext::decode(&mut &ciphertext_buf[..])?;

            Ok(Command {
                enclave_sig,
                ciphertext,
            })
        }
    }

    impl Command {
        pub fn new(ciphertext: Ciphertext, enclave_sig: secp256k1::Signature) -> Self {
            Command {
                enclave_sig,
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

    #[derive(Encode, Decode, Debug, Clone)]
    pub struct ReturnEncryptingKey {
        encrypting_key: DhPubKey,
    }

    impl EcallOutput for ReturnEncryptingKey {}

    impl ReturnEncryptingKey {
        pub fn new(encrypting_key: DhPubKey) -> Self {
            ReturnEncryptingKey { encrypting_key }
        }

        pub fn encrypting_key(self) -> DhPubKey {
            self.encrypting_key
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
        mrenclave_ver: u32,
        roster_idx: u32,
        export_path_secret: ExportPathSecret,
    }

    impl EcallOutput for ReturnJoinGroup {}

    impl ReturnJoinGroup {
        pub fn new(
            report: Vec<u8>,
            report_sig: Vec<u8>,
            handshake: Vec<u8>,
            mrenclave_ver: usize,
            roster_idx: u32,
            export_path_secret: ExportPathSecret,
        ) -> Self {
            ReturnJoinGroup {
                report,
                report_sig,
                handshake,
                mrenclave_ver: mrenclave_ver as u32,
                roster_idx,
                export_path_secret,
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

        pub fn mrenclave_ver(&self) -> u32 {
            self.mrenclave_ver
        }

        pub fn export_path_secret_as_ref(&self) -> &ExportPathSecret {
            &self.export_path_secret
        }

        pub fn export_path_secret(self) -> ExportPathSecret {
            self.export_path_secret
        }

        pub fn roster_idx(&self) -> u32 {
            self.roster_idx
        }
    }

    #[derive(Debug, Clone)]
    pub struct ReturnHandshake {
        export_path_secret: ExportPathSecret,
        enclave_sig: secp256k1::Signature,
        roster_idx: u32,
        handshake: ExportHandshake,
    }

    impl EcallOutput for ReturnHandshake {}

    impl Encode for ReturnHandshake {
        fn encode(&self) -> Vec<u8> {
            let mut acc = vec![];
            acc.extend_from_slice(&self.export_path_secret_as_ref().encode());
            acc.extend_from_slice(&self.encode_enclave_sig());
            acc.extend_from_slice(&self.roster_idx().encode());
            acc.extend_from_slice(&self.encode_handshake());

            acc
        }
    }

    impl Decode for ReturnHandshake {
        fn decode<I: Input>(value: &mut I) -> Result<Self, codec::Error> {
            let export_path_secret = ExportPathSecret::decode(value)?;

            let mut enclave_sig_buf = [0u8; 64];
            value.read(&mut enclave_sig_buf)?;
            let enclave_sig = secp256k1::Signature::parse(&enclave_sig_buf);

            let roster_idx = u32::decode(value)?;
            let handshake = ExportHandshake::decode(value)?;

            Ok(ReturnHandshake {
                export_path_secret,
                enclave_sig,
                roster_idx,
                handshake,
            })
        }
    }

    impl ReturnHandshake {
        pub fn new(
            handshake: ExportHandshake,
            export_path_secret: ExportPathSecret,
            enclave_sig: secp256k1::Signature,
            roster_idx: u32,
        ) -> Self {
            ReturnHandshake {
                handshake,
                export_path_secret,
                enclave_sig,
                roster_idx,
            }
        }

        pub fn handshake(&self) -> &ExportHandshake {
            &self.handshake
        }

        pub fn encode_handshake(&self) -> Vec<u8> {
            self.handshake.encode()
        }

        pub fn export_path_secret_as_ref(&self) -> &ExportPathSecret {
            &self.export_path_secret
        }

        pub fn export_path_secret(self) -> ExportPathSecret {
            self.export_path_secret
        }

        pub fn encode_enclave_sig(&self) -> [u8; 64] {
            self.enclave_sig.serialize()
        }

        pub fn roster_idx(&self) -> u32 {
            self.roster_idx
        }
    }
}
