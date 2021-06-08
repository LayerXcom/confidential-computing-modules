use anonify_ecall_types::*;
use frame_common::{
    crypto::{AccountId, ExportHandshake},
    state_types::StateCounter,
};
use frame_host::ecall_controller::*;
use frame_sodium::SodiumCiphertext;
use web3::types::Address;

pub const EI_MAX_SIZE: usize = 2048;

pub struct CommandWorkflow;

impl EcallController for CommandWorkflow {
    type HI = host_input::Command;
    type EI = input::Command;
    type EO = output::Command;
    type HO = host_output::Command;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::Command::new(
            host_input.ciphertext,
            host_input.user_id,
        ))
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::Command { enclave_output })
    }
}

pub struct JoinGroupWorkflow;

impl EcallController for JoinGroupWorkflow {
    type HI = host_input::JoinGroup;
    type EI = input::Empty;
    type EO = output::ReturnJoinGroup;
    type HO = host_output::JoinGroup;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(input::Empty::default())
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(host_output::JoinGroup { enclave_output })
    }
}

pub struct RegisterReportWorkflow;

impl EcallController for RegisterReportWorkflow {
    type HI = host_input::RegisterReport;
    type EI = input::Empty;
    type EO = output::ReturnRegisterReport;
    type HO = host_output::RegisterReport;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct HandshakeWorkflow;

impl EcallController for HandshakeWorkflow {
    type HI = host_input::Handshake;
    type EI = input::Empty;
    type EO = output::ReturnHandshake;
    type HO = host_output::Handshake;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct RegisterNotificationWorkflow;

impl EcallController for RegisterNotificationWorkflow {
    type HI = host_input::RegisterNotification;
    type EI = SodiumCiphertext;
    type EO = output::Empty;
    type HO = host_output::RegisterNotification;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct GetStateWorkflow;

impl EcallController for GetStateWorkflow {
    type HI = host_input::GetState;
    type EI = SodiumCiphertext;
    type EO = output::ReturnState;
    type HO = host_output::GetState;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct InsertCiphertextWorkflow;

impl EcallController for InsertCiphertextWorkflow {
    type HI = host_input::InsertCiphertext;
    type EI = input::InsertCiphertext;
    type EO = output::ReturnNotifyState;
    type HO = host_output::InsertCiphertext;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct InsertHandshakeWorkflow;

impl EcallController for InsertHandshakeWorkflow {
    type HI = host_input::InsertHandshake;
    type EI = input::InsertHandshake;
    type EO = output::Empty;
    type HO = host_output::InsertHandshake;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct GetEncryptionKeyWorkflow;

impl EcallController for GetEncryptionKeyWorkflow {
    type HI = host_input::GetEncryptionKey;
    type EI = input::Empty;
    type EO = output::ReturnEncryptionKey;
    type HO = host_output::ReturnEncryptionKey;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct BackupWorkflow;

impl EcallController for BackupWorkflow {
    type HI = host_input::Backup;
    type EI = input::Empty;
    type EO = output::Empty;
    type HO = host_output::Backup;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct RecoverWorkflow;

impl EcallController for RecoverWorkflow {
    type HI = host_input::Recover;
    type EI = input::Empty;
    type EO = output::Empty;
    type HO = host_output::Recover;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct GetUserCounterWorkflow;

impl EcallController for GetUserCounterWorkflow {
    type HI = host_input::GetUserCounter;
    type EI = SodiumCiphertext;
    type EO = output::ReturnUserCounter;
    type HO = host_output::GetUserCounter;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub mod host_input {
    use super::*;

    pub struct Command {
        ciphertext: SodiumCiphertext,
        user_id: Option<AccountId>,
        ecall_cmd: u32,
    }

    impl Command {
        pub fn new(
            ciphertext: SodiumCiphertext,
            user_id: Option<AccountId>,
            ecall_cmd: u32,
        ) -> Self {
            Command {
                ciphertext,
                user_id,
                ecall_cmd,
            }
        }
    }

    impl HostInput for Command {
        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct JoinGroup {
        ecall_cmd: u32,
    }

    impl JoinGroup {
        pub fn new(ecall_cmd: u32) -> Self {
            JoinGroup { ecall_cmd }
        }
    }

    impl HostInput for JoinGroup {
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
        type EnclaveInput = input::Empty;
        type HostOutput = host_output::RegisterReport;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            let host_output = host_output::RegisterReport::new(self.signer, self.gas);

            Ok((Self::EnclaveInput::default(), host_output))
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
        type EnclaveInput = input::Empty;
        type HostOutput = host_output::Handshake;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            let host_output = host_output::Handshake::new(self.signer, self.gas);

            Ok((Self::EnclaveInput::default(), host_output))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct RegisterNotification {
        ciphertext: SodiumCiphertext,
        ecall_cmd: u32,
    }

    impl RegisterNotification {
        pub fn new(ciphertext: SodiumCiphertext, ecall_cmd: u32) -> Self {
            RegisterNotification {
                ciphertext,
                ecall_cmd,
            }
        }
    }

    impl HostInput for RegisterNotification {
        type EnclaveInput = SodiumCiphertext;
        type HostOutput = host_output::RegisterNotification;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            Ok((self.ciphertext, Self::HostOutput::default()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct GetState {
        ciphertext: SodiumCiphertext,
        ecall_cmd: u32,
    }

    impl GetState {
        pub fn new(ciphertext: SodiumCiphertext, ecall_cmd: u32) -> Self {
            GetState {
                ciphertext,
                ecall_cmd,
            }
        }
    }

    impl HostInput for GetState {
        type EnclaveInput = SodiumCiphertext;
        type HostOutput = host_output::GetState;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            Ok((self.ciphertext, Self::HostOutput::new()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct GetUserCounter {
        ciphertext: SodiumCiphertext,
        ecall_cmd: u32,
    }

    impl GetUserCounter {
        pub fn new(ciphertext: SodiumCiphertext, ecall_cmd: u32) -> Self {
            GetUserCounter {
                ciphertext,
                ecall_cmd,
            }
        }
    }

    impl HostInput for GetUserCounter {
        type EnclaveInput = SodiumCiphertext;
        type HostOutput = host_output::GetUserCounter;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            Ok((self.ciphertext, Self::HostOutput::new()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct InsertCiphertext {
        ciphertext: CommandCiphertext,
        state_counter: StateCounter,
        ecall_cmd: u32,
    }

    impl InsertCiphertext {
        pub fn new(
            ciphertext: CommandCiphertext,
            state_counter: StateCounter,
            ecall_cmd: u32,
        ) -> Self {
            InsertCiphertext {
                ciphertext,
                state_counter,
                ecall_cmd,
            }
        }
    }

    impl HostInput for InsertCiphertext {
        type EnclaveInput = input::InsertCiphertext;
        type HostOutput = host_output::InsertCiphertext;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            let enclave_input = Self::EnclaveInput::new(self.ciphertext, self.state_counter);

            Ok((enclave_input, Self::HostOutput::new()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct InsertHandshake {
        handshake: ExportHandshake,
        state_counter: StateCounter,
        ecall_cmd: u32,
    }

    impl InsertHandshake {
        pub fn new(
            handshake: ExportHandshake,
            state_counter: StateCounter,
            ecall_cmd: u32,
        ) -> Self {
            InsertHandshake {
                handshake,
                state_counter,
                ecall_cmd,
            }
        }
    }

    impl HostInput for InsertHandshake {
        type EnclaveInput = input::InsertHandshake;
        type HostOutput = host_output::InsertHandshake;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            let enclave_input = Self::EnclaveInput::new(self.handshake, self.state_counter);

            Ok((enclave_input, Self::HostOutput::default()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct GetEncryptionKey {
        ecall_cmd: u32,
    }

    impl GetEncryptionKey {
        pub fn new(ecall_cmd: u32) -> Self {
            GetEncryptionKey { ecall_cmd }
        }
    }

    impl HostInput for GetEncryptionKey {
        type EnclaveInput = input::Empty;
        type HostOutput = host_output::ReturnEncryptionKey;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            Ok((Self::EnclaveInput::default(), Self::HostOutput::new()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct Backup {
        ecall_cmd: u32,
    }

    impl Backup {
        pub fn new(ecall_cmd: u32) -> Self {
            Backup { ecall_cmd }
        }
    }

    impl HostInput for Backup {
        type EnclaveInput = input::Empty;
        type HostOutput = host_output::Backup;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            Ok((Self::EnclaveInput::default(), Self::HostOutput::default()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct Recover {
        ecall_cmd: u32,
    }

    impl Recover {
        pub fn new(ecall_cmd: u32) -> Self {
            Recover { ecall_cmd }
        }
    }

    impl HostInput for Recover {
        type EnclaveInput = input::Empty;
        type HostOutput = host_output::Recover;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            Ok((Self::EnclaveInput::default(), Self::HostOutput::default()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }
}

pub mod host_output {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Command {
        pub enclave_output: output::Command,
    }

    impl HostOutput for Command {}

    #[derive(Debug, Clone)]
    pub struct JoinGroup {
        pub enclave_output: output::ReturnJoinGroup,
    }

    impl HostOutput for JoinGroup {}

    #[derive(Debug, Clone)]
    pub struct RegisterReport {
        pub signer: Address,
        pub gas: u64,
        pub ecall_output: Option<output::ReturnRegisterReport>,
    }

    impl HostOutput for RegisterReport {
        type EnclaveOutput = output::ReturnRegisterReport;

        fn set_ecall_output(mut self, output: Self::EnclaveOutput) -> anyhow::Result<Self> {
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
        type EnclaveOutput = output::ReturnHandshake;

        fn set_ecall_output(mut self, output: Self::EnclaveOutput) -> anyhow::Result<Self> {
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
        type EnclaveOutput = output::Empty;
    }

    pub struct GetState {
        pub ecall_output: Option<output::ReturnState>,
    }

    impl HostOutput for GetState {
        type EnclaveOutput = output::ReturnState;

        fn set_ecall_output(mut self, output: Self::EnclaveOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl GetState {
        pub fn new() -> Self {
            GetState { ecall_output: None }
        }
    }

    pub struct GetUserCounter {
        pub ecall_output: Option<output::ReturnUserCounter>,
    }

    impl HostOutput for GetUserCounter {
        type EnclaveOutput = output::ReturnUserCounter;

        fn set_ecall_output(mut self, output: Self::EnclaveOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl GetUserCounter {
        pub fn new() -> Self {
            GetUserCounter { ecall_output: None }
        }
    }

    pub struct InsertCiphertext {
        pub ecall_output: Option<output::ReturnNotifyState>,
    }

    impl HostOutput for InsertCiphertext {
        type EnclaveOutput = output::ReturnNotifyState;

        fn set_ecall_output(mut self, output: Self::EnclaveOutput) -> anyhow::Result<Self> {
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
        type EnclaveOutput = output::Empty;
    }

    pub struct ReturnEncryptionKey {
        pub ecall_output: Option<output::ReturnEncryptionKey>,
    }

    impl HostOutput for ReturnEncryptionKey {
        type EnclaveOutput = output::ReturnEncryptionKey;

        fn set_ecall_output(mut self, output: Self::EnclaveOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl ReturnEncryptionKey {
        pub fn new() -> Self {
            ReturnEncryptionKey { ecall_output: None }
        }
    }

    #[derive(Default)]
    pub struct Backup;

    impl HostOutput for Backup {
        type EnclaveOutput = output::Empty;
    }

    #[derive(Default)]
    pub struct Recover;

    impl HostOutput for Recover {
        type EnclaveOutput = output::Empty;
    }
}
