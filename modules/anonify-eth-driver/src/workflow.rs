use crate::utils::CommandInfo;
use anonify_io_types::*;
use frame_common::{
    crypto::{Ciphertext, ExportHandshake},
    traits::*,
};
use frame_host::engine::*;
use frame_treekem::EciesCiphertext;
use std::marker::PhantomData;
use web3::types::Address;

pub const OUTPUT_MAX_LEN: usize = 2048;

pub struct CommandWorkflow<C: CallNameConverter, AP: AccessPolicy> {
    c: PhantomData<C>,
    ap: PhantomData<AP>,
}

impl<C: CallNameConverter, AP: AccessPolicy> HostEngine for CommandWorkflow<C, AP> {
    type HI = host_input::Command<C, AP>;
    type EI = input::Command<AP>;
    type EO = output::Command;
    type HO = host_output::Command;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct JoinGroupWorkflow;

impl HostEngine for JoinGroupWorkflow {
    type HI = host_input::JoinGroup;
    type EI = input::CallJoinGroup;
    type EO = output::ReturnJoinGroup;
    type HO = host_output::JoinGroup;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct RegisterReportWorkflow;

impl HostEngine for RegisterReportWorkflow {
    type HI = host_input::RegisterReport;
    type EI = input::CallRegisterReport;
    type EO = output::ReturnRegisterReport;
    type HO = host_output::RegisterReport;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct HandshakeWorkflow;

impl HostEngine for HandshakeWorkflow {
    type HI = host_input::Handshake;
    type EI = input::CallHandshake;
    type EO = output::ReturnHandshake;
    type HO = host_output::Handshake;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct RegisterNotificationWorkflow<AP: AccessPolicy> {
    ap: PhantomData<AP>,
}

impl<AP: AccessPolicy> HostEngine for RegisterNotificationWorkflow<AP> {
    type HI = host_input::RegisterNotification<AP>;
    type EI = input::RegisterNotification<AP>;
    type EO = output::Empty;
    type HO = host_output::RegisterNotification;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct GetStateWorkflow<AP: AccessPolicy> {
    ap: PhantomData<AP>,
}

impl<AP: AccessPolicy> HostEngine for GetStateWorkflow<AP> {
    type HI = host_input::GetState<AP>;
    type EI = input::GetState<AP>;
    type EO = output::ReturnState;
    type HO = host_output::GetState;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct InsertCiphertextWorkflow;

impl HostEngine for InsertCiphertextWorkflow {
    type HI = host_input::InsertCiphertext;
    type EI = input::InsertCiphertext;
    type EO = output::ReturnUpdatedState;
    type HO = host_output::InsertCiphertext;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct InsertHandshakeWorkflow;

impl HostEngine for InsertHandshakeWorkflow {
    type HI = host_input::InsertHandshake;
    type EI = input::InsertHandshake;
    type EO = output::Empty;
    type HO = host_output::InsertHandshake;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct GetEncryptingKeyWorkflow;

impl HostEngine for GetEncryptingKeyWorkflow {
    type HI = host_input::GetEncryptingKey;
    type EI = input::GetEncryptingKey;
    type EO = output::ReturnEncryptingKey;
    type HO = host_output::ReturnEncryptingKey;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct BackupPathSecretAllWorkflow;

impl HostEngine for BackupPathSecretAllWorkflow {
    type HI = host_input::BackupPathSecretAll;
    type EI = input::BackupPathSecretAll;
    type EO = output::Empty;
    type HO = host_output::BackupPathSecretAll;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = BACKUP_PATH_SECRET_ALL_CMD;
}

pub struct RecoverPathSecretAllWorkflow;

impl HostEngine for RecoverPathSecretAllWorkflow {
    type HI = host_input::RecoverPathSecretAll;
    type EI = input::RecoverPathSecretAll;
    type EO = output::Empty;
    type HO = host_output::RecoverPathSecretAll;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = RECOVER_PATH_SECRET_ALL_CMD;
}

pub mod host_input {
    use super::*;

    pub struct Command<C: CallNameConverter, AP: AccessPolicy> {
        encrypted_command: EciesCiphertext,
        call_name: String,
        access_policy: AP,
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
        phantom: PhantomData<C>,
    }

    impl<C: CallNameConverter, AP: AccessPolicy> Command<C, AP> {
        pub fn new(
            encrypted_command: EciesCiphertext,
            call_name: String,
            access_policy: AP,
            signer: Address,
            gas: u64,
            ecall_cmd: u32,
        ) -> Self {
            Command {
                encrypted_command,
                call_name,
                access_policy,
                signer,
                gas,
                ecall_cmd,
                phantom: PhantomData,
            }
        }
    }

    impl<C: CallNameConverter, AP: AccessPolicy> HostInput for Command<C, AP> {
        type EcallInput = input::Command<AP>;
        type HostOutput = host_output::Command;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let command_info = CommandInfo::<C>::new(self.encrypted_command, &self.call_name);
            let ecall_input = command_info.crate_input(self.access_policy);
            let host_output = host_output::Command::new(self.signer, self.gas);

            Ok((ecall_input, host_output))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct JoinGroup {
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
    }

    impl JoinGroup {
        pub fn new(signer: Address, gas: u64, ecall_cmd: u32) -> Self {
            JoinGroup {
                signer,
                gas,
                ecall_cmd,
            }
        }
    }

    impl HostInput for JoinGroup {
        type EcallInput = input::CallJoinGroup;
        type HostOutput = host_output::JoinGroup;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let host_output = host_output::JoinGroup::new(self.signer, self.gas);

            Ok((Self::EcallInput::default(), host_output))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct RegisterReport {
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
    }

    impl RegisterReport {
        pub fn new(signer: Address, gas: u64, ecall_cmd: u32) -> Self {
            RegisterReport {
                signer,
                gas,
                ecall_cmd,
            }
        }
    }

    impl HostInput for RegisterReport {
        type EcallInput = input::CallRegisterReport;
        type HostOutput = host_output::RegisterReport;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let host_output = host_output::RegisterReport::new(self.signer, self.gas);

            Ok((Self::EcallInput::default(), host_output))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct Handshake {
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
    }

    impl Handshake {
        pub fn new(signer: Address, gas: u64, ecall_cmd: u32) -> Self {
            Handshake {
                signer,
                gas,
                ecall_cmd,
            }
        }
    }

    impl HostInput for Handshake {
        type EcallInput = input::CallHandshake;
        type HostOutput = host_output::Handshake;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let host_output = host_output::Handshake::new(self.signer, self.gas);

            Ok((Self::EcallInput::default(), host_output))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct RegisterNotification<AP: AccessPolicy> {
        access_policy: AP,
        ecall_cmd: u32,
    }

    impl<AP: AccessPolicy> RegisterNotification<AP> {
        pub fn new(access_policy: AP, ecall_cmd: u32) -> Self {
            RegisterNotification {
                access_policy,
                ecall_cmd,
            }
        }
    }

    impl<AP: AccessPolicy> HostInput for RegisterNotification<AP> {
        type EcallInput = input::RegisterNotification<AP>;
        type HostOutput = host_output::RegisterNotification;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.access_policy);

            Ok((ecall_input, Self::HostOutput::default()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct GetState<AP: AccessPolicy> {
        access_policy: AP,
        call_id: u32,
        ecall_cmd: u32,
    }

    impl<AP: AccessPolicy> GetState<AP> {
        pub fn new(access_policy: AP, call_id: u32, ecall_cmd: u32) -> Self {
            GetState {
                access_policy,
                call_id,
                ecall_cmd,
            }
        }
    }

    impl<AP: AccessPolicy> HostInput for GetState<AP> {
        type EcallInput = input::GetState<AP>;
        type HostOutput = host_output::GetState;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.access_policy, self.call_id);

            Ok((ecall_input, Self::HostOutput::new()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct InsertCiphertext {
        ciphertext: Ciphertext,
        ecall_cmd: u32,
    }

    impl InsertCiphertext {
        pub fn new(ciphertext: Ciphertext, ecall_cmd: u32) -> Self {
            InsertCiphertext {
                ciphertext,
                ecall_cmd,
            }
        }
    }

    impl HostInput for InsertCiphertext {
        type EcallInput = input::InsertCiphertext;
        type HostOutput = host_output::InsertCiphertext;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.ciphertext);

            Ok((ecall_input, Self::HostOutput::new()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct InsertHandshake {
        handshake: ExportHandshake,
        ecall_cmd: u32,
    }

    impl InsertHandshake {
        pub fn new(handshake: ExportHandshake, ecall_cmd: u32) -> Self {
            InsertHandshake {
                handshake,
                ecall_cmd,
            }
        }
    }

    impl HostInput for InsertHandshake {
        type EcallInput = input::InsertHandshake;
        type HostOutput = host_output::InsertHandshake;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.handshake);

            Ok((ecall_input, Self::HostOutput::default()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    #[derive(Default)]
    pub struct GetEncryptingKey {
        ecall_cmd: u32,
    }

    impl GetEncryptingKey {
        pub fn new(ecall_cmd: u32) -> Self {
            GetEncryptingKey { ecall_cmd }
        }
    }

    impl HostInput for GetEncryptingKey {
        type EcallInput = input::GetEncryptingKey;
        type HostOutput = host_output::ReturnEncryptingKey;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            Ok((Self::EcallInput::default(), Self::HostOutput::new()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    #[derive(Default)]
    pub struct BackupPathSecretAll;

    impl HostInput for BackupPathSecretAll {
        type EcallInput = input::BackupPathSecretAll;
        type HostOutput = host_output::BackupPathSecretAll;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            Ok((Self::EcallInput::default(), Self::HostOutput::default()))
        }
    }

    #[derive(Default)]
    pub struct RecoverPathSecretAll;

    impl HostInput for RecoverPathSecretAll {
        type EcallInput = input::RecoverPathSecretAll;
        type HostOutput = host_output::RecoverPathSecretAll;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            Ok((Self::EcallInput::default(), Self::HostOutput::default()))
        }
    }
}

pub mod host_output {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Command {
        pub signer: Address,
        pub gas: u64,
        pub ecall_output: Option<output::Command>,
    }

    impl HostOutput for Command {
        type EcallOutput = output::Command;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl Command {
        pub fn new(signer: Address, gas: u64) -> Self {
            Command {
                signer,
                gas,
                ecall_output: None,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct JoinGroup {
        pub signer: Address,
        pub gas: u64,
        pub ecall_output: Option<output::ReturnJoinGroup>,
    }

    impl HostOutput for JoinGroup {
        type EcallOutput = output::ReturnJoinGroup;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl JoinGroup {
        pub fn new(signer: Address, gas: u64) -> Self {
            JoinGroup {
                signer,
                gas,
                ecall_output: None,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct RegisterReport {
        pub signer: Address,
        pub gas: u64,
        pub ecall_output: Option<output::ReturnRegisterReport>,
    }

    impl HostOutput for RegisterReport {
        type EcallOutput = output::ReturnRegisterReport;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl RegisterReport {
        pub fn new(signer: Address, gas: u64) -> Self {
            RegisterReport {
                signer,
                gas,
                ecall_output: None,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct Handshake {
        pub signer: Address,
        pub gas: u64,
        pub ecall_output: Option<output::ReturnHandshake>,
    }

    impl HostOutput for Handshake {
        type EcallOutput = output::ReturnHandshake;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl Handshake {
        pub fn new(signer: Address, gas: u64) -> Self {
            Handshake {
                signer,
                gas,
                ecall_output: None,
            }
        }
    }

    #[derive(Default)]
    pub struct RegisterNotification;

    impl HostOutput for RegisterNotification {
        type EcallOutput = output::Empty;
    }

    pub struct GetState {
        pub ecall_output: Option<output::ReturnState>,
    }

    impl HostOutput for GetState {
        type EcallOutput = output::ReturnState;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl GetState {
        pub fn new() -> Self {
            GetState { ecall_output: None }
        }
    }

    pub struct InsertCiphertext {
        pub ecall_output: Option<output::ReturnUpdatedState>,
    }

    impl HostOutput for InsertCiphertext {
        type EcallOutput = output::ReturnUpdatedState;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl InsertCiphertext {
        pub fn new() -> Self {
            InsertCiphertext { ecall_output: None }
        }
    }

    #[derive(Default)]
    pub struct InsertHandshake;

    impl HostOutput for InsertHandshake {
        type EcallOutput = output::Empty;
    }

    pub struct ReturnEncryptingKey {
        pub ecall_output: Option<output::ReturnEncryptingKey>,
    }

    impl HostOutput for ReturnEncryptingKey {
        type EcallOutput = output::ReturnEncryptingKey;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl ReturnEncryptingKey {
        pub fn new() -> Self {
            ReturnEncryptingKey { ecall_output: None }
        }
    }

    #[derive(Default)]
    pub struct BackupPathSecretAll;

    impl HostOutput for BackupPathSecretAll {
        type EcallOutput = output::Empty;
    }

    #[derive(Default)]
    pub struct RecoverPathSecretAll;

    impl HostOutput for RecoverPathSecretAll {
        type EcallOutput = output::Empty;
    }
}
