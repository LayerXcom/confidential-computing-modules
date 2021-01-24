use crate::localstd::{
    fmt, str,
    string::{String, ToString},
    vec::Vec,
};
use crate::serde::{
    de::{self, SeqAccess},
    Deserialize, Serialize, Serializer,
};
use crate::serde_bytes;
use crate::serde_json;
use frame_common::{
    crypto::{Ciphertext, ExportHandshake},
    state_types::{StateType, UpdatedState},
    traits::AccessPolicy,
    EcallInput, EcallOutput,
};
use frame_treekem::DhPubKey;

pub mod input {
    use super::*;

    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(crate = "crate::serde")]
    pub struct Command<AP: AccessPolicy> {
        #[serde(deserialize_with = "AP::deserialize")]
        pub access_policy: AP,
        pub runtime_command: serde_json::Value,
        pub cmd_name: String,
    }

    impl<AP> Default for Command<AP>
    where
        AP: AccessPolicy,
    {
        fn default() -> Self {
            Self {
                access_policy: AP::default(),
                runtime_command: serde_json::Value::Null,
                cmd_name: String::default(),
            }
        }
    }

    impl<AP> EcallInput for Command<AP> where AP: AccessPolicy {}

    impl<AP> Command<AP>
    where
        AP: AccessPolicy,
    {
        pub fn new(
            access_policy: AP,
            runtime_command: serde_json::Value,
            cmd_name: impl ToString,
        ) -> Self {
            Command {
                access_policy,
                runtime_command,
                cmd_name: cmd_name.to_string(),
            }
        }

        pub fn access_policy(&self) -> &AP {
            &self.access_policy
        }

        pub fn cmd_name(&self) -> &str {
            &self.cmd_name
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct GetEncryptingKey;

    impl EcallInput for GetEncryptingKey {}

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct CallHandshake;

    impl EcallInput for CallHandshake {}

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct CallJoinGroup;

    impl EcallInput for CallJoinGroup {}

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct CallRegisterReport;

    impl EcallInput for CallRegisterReport {}

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
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

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
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

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct GetState<AP: AccessPolicy> {
        #[serde(deserialize_with = "AP::deserialize")]
        access_policy: AP,
        cmd_name: String,
    }

    impl<AP: AccessPolicy> EcallInput for GetState<AP> {}

    impl<AP: AccessPolicy> GetState<AP> {
        pub fn new(access_policy: AP, cmd_name: String) -> Self {
            GetState {
                access_policy,
                cmd_name: cmd_name.into_bytes(),
            }
        }

        pub fn access_policy(&self) -> &AP {
            &self.access_policy
        }

        pub fn cmd_name(&self) -> &str {
            &self.cmd_name
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct RegisterNotification<AP: AccessPolicy> {
        #[serde(deserialize_with = "AP::deserialize")]
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

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct BackupPathSecretAll;

    impl EcallInput for BackupPathSecretAll {}

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct RecoverPathSecretAll;

    impl EcallInput for RecoverPathSecretAll {}
}

pub mod output {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Command {
        enclave_sig: secp256k1::Signature,
        ciphertext: Ciphertext,
        recovery_id: secp256k1::RecoveryId,
    }

    impl Default for Command {
        fn default() -> Self {
            let enclave_sig = secp256k1::Signature::parse(&[0u8; 64]);
            let recovery_id = secp256k1::RecoveryId::parse(0).unwrap();
            Self {
                enclave_sig,
                ciphertext: Ciphertext::default(),
                recovery_id,
            }
        }
    }

    impl EcallOutput for Command {}

    impl Serialize for Command {
        // not for human readable, used for binary encoding
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(3))?;
            seq.serialize_element(self.encode_enclave_sig())?;
            seq.serialize_element(self.encode_recovery_id())?;
            seq.serialize_element(self.encode_ciphertext())?;
            seq.end()
        }
    }

    impl<'de> Deserialize<'de> for Command {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct CommandVisitor;

            impl<'de> de::Visitor<'de> for CommandVisitor {
                type Value = Command;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("ecall output command")
                }

                fn visit_seq<V>(self, mut seq: V) -> Result<Command, V::Error>
                where
                    V: SeqAccess<'de>,
                {
                    let enclave_sig_v = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                    let recovery_id_v = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    let ciphertext_v = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                    let enclave_sig = secp256k1::Signature::parse(enclave_sig_v);
                    let recovery_id = secp256k1::RecoveryId::parse(recovery_id_v)
                        .map_err(|_e| V::Error::custom(secp256k1::Error::InvalidRecoveryId))?;
                    let ciphertext = bincode::deserialize(&ciphertext_v[..])?;

                    Ok(Command::new(ciphertext, enclave_sig, recovery_id))
                }
            }
        }
    }

    impl Command {
        pub fn new(
            ciphertext: Ciphertext,
            enclave_sig: secp256k1::Signature,
            recovery_id: secp256k1::RecoveryId,
        ) -> Self {
            Command {
                enclave_sig,
                ciphertext,
                recovery_id,
            }
        }

        pub fn ciphertext(&self) -> &Ciphertext {
            &self.ciphertext
        }

        pub fn encode_ciphertext(&self) -> Vec<u8> {
            self.ciphertext.encode()
        }

        pub fn encode_recovery_id(&self) -> u8 {
            self.recovery_id.serialize()
        }

        pub fn encode_enclave_sig(&self) -> [u8; 64] {
            self.enclave_sig.serialize()
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    #[serde(crate = "crate::serde")]
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

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
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

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct Empty;

    impl EcallOutput for Empty {}

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
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

    #[derive(Serialize, Deserialize, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct ReturnJoinGroup {
        #[serde(with = "serde_bytes")]
        report: Vec<u8>,
        #[serde(with = "serde_bytes")]
        report_sig: Vec<u8>,
        #[serde(with = "serde_bytes")]
        handshake: Vec<u8>,
        mrenclave_ver: u32,
        roster_idx: u32,
    }

    impl fmt::Debug for ReturnJoinGroup {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "ReturnJoinGroup {{ report: 0x{}, report_sig: 0x{}, handshake: 0x{}, mrenclave_ver: {:?}, roster_idx: {:?} }}",
                hex::encode(&self.report()),
                hex::encode(&self.report_sig()),
                hex::encode(&self.handshake),
                self.mrenclave_ver,
                self.roster_idx
            )
        }
    }

    impl EcallOutput for ReturnJoinGroup {}

    impl ReturnJoinGroup {
        pub fn new(
            report: Vec<u8>,
            report_sig: Vec<u8>,
            handshake: Vec<u8>,
            mrenclave_ver: usize,
            roster_idx: u32,
        ) -> Self {
            ReturnJoinGroup {
                report,
                report_sig,
                handshake,
                mrenclave_ver: mrenclave_ver as u32,
                roster_idx,
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

        pub fn roster_idx(&self) -> u32 {
            self.roster_idx
        }
    }

    #[derive(Serialize, Deserialize, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct ReturnRegisterReport {
        #[serde(with = "serde_bytes")]
        report: Vec<u8>,
        #[serde(with = "serde_bytes")]
        report_sig: Vec<u8>,
        mrenclave_ver: u32,
        roster_idx: u32,
    }

    impl fmt::Debug for ReturnRegisterReport {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "ReturnRegisterReport {{ report: 0x{}, report_sig: 0x{}, mrenclave_ver: {:?}, roster_idx: {:?} }}",
                hex::encode(&self.report),
                hex::encode(&self.report_sig),
                self.mrenclave_ver,
                self.roster_idx
            )
        }
    }

    impl EcallOutput for ReturnRegisterReport {}

    impl ReturnRegisterReport {
        pub fn new(
            report: Vec<u8>,
            report_sig: Vec<u8>,
            mrenclave_ver: usize,
            roster_idx: u32,
        ) -> Self {
            ReturnRegisterReport {
                report,
                report_sig,
                mrenclave_ver: mrenclave_ver as u32,
                roster_idx,
            }
        }

        pub fn report(&self) -> &[u8] {
            &self.report[..]
        }

        pub fn report_sig(&self) -> &[u8] {
            &self.report_sig[..]
        }

        pub fn mrenclave_ver(&self) -> u32 {
            self.mrenclave_ver
        }

        pub fn roster_idx(&self) -> u32 {
            self.roster_idx
        }
    }

    #[derive(Debug, Clone)]
    pub struct ReturnHandshake {
        enclave_sig: secp256k1::Signature,
        recovery_id: secp256k1::RecoveryId,
        roster_idx: u32,
        handshake: ExportHandshake,
    }

    impl Default for ReturnHandshake {
        fn default() -> Self {
            let enclave_sig = secp256k1::Signature::parse(&[0u8; 64]);
            let recovery_id = secp256k1::RecoveryId::parse(0).unwrap();
            Self {
                enclave_sig,
                recovery_id,
                roster_idx: u32::default(),
                handshake: ExportHandshake::default(),
            }
        }
    }

    impl EcallOutput for ReturnHandshake {}

    impl Encode for ReturnHandshake {
        fn encode(&self) -> Vec<u8> {
            let mut acc = vec![];
            acc.extend_from_slice(&self.encode_enclave_sig());
            acc.push(self.encode_recovery_id());
            acc.extend_from_slice(&self.roster_idx().encode());
            acc.extend_from_slice(&self.encode_handshake());

            acc
        }
    }

    impl Decode for ReturnHandshake {
        fn decode<I: Input>(value: &mut I) -> Result<Self, codec::Error> {
            let mut enclave_sig_buf = [0u8; 64];
            value.read(&mut enclave_sig_buf)?;
            let enclave_sig = secp256k1::Signature::parse(&enclave_sig_buf);

            let recovery_id_buf = value.read_byte()?;
            let recovery_id = secp256k1::RecoveryId::parse(recovery_id_buf)
                .map_err(|_| codec::Error::from("Failed to parse recovery_id"))?;

            let roster_idx = u32::decode(value)?;
            let handshake = ExportHandshake::decode(value)?;

            Ok(ReturnHandshake {
                enclave_sig,
                recovery_id,
                roster_idx,
                handshake,
            })
        }
    }

    impl ReturnHandshake {
        pub fn new(
            handshake: ExportHandshake,
            enclave_sig: secp256k1::Signature,
            recovery_id: secp256k1::RecoveryId,
            roster_idx: u32,
        ) -> Self {
            ReturnHandshake {
                handshake,
                enclave_sig,
                recovery_id,
                roster_idx,
            }
        }

        pub fn handshake(&self) -> &ExportHandshake {
            &self.handshake
        }

        pub fn encode_handshake(&self) -> Vec<u8> {
            self.handshake.encode()
        }

        pub fn encode_recovery_id(&self) -> u8 {
            self.recovery_id.serialize()
        }

        pub fn encode_enclave_sig(&self) -> [u8; 64] {
            self.enclave_sig.serialize()
        }

        pub fn roster_idx(&self) -> u32 {
            self.roster_idx
        }
    }
}
