use anonify_ecall_types::*;
use frame_common::{
    crypto::{Ciphertext, ExportHandshake},
    state_types::StateCounter,
};
use frame_host::engine::*;
use frame_sodium::SodiumCiphertext;
use web3::types::Address;

pub const OUTPUT_MAX_LEN: usize = 1_000_000;

pub struct CommandWorkflow;

impl HostEngine for CommandWorkflow {
    type HI = host_input::Command;
    type EI = SodiumCiphertext;
    type EO = output::Command;
    type HO = host_output::Command;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct JoinGroupWorkflow;

impl HostEngine for JoinGroupWorkflow {
    type HI = host_input::JoinGroup;
    type EI = input::Empty;
    type EO = output::ReturnJoinGroup;
    type HO = host_output::JoinGroup;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct RegisterReportWorkflow;

impl HostEngine for RegisterReportWorkflow {
    type HI = host_input::RegisterReport;
    type EI = input::Empty;
    type EO = output::ReturnRegisterReport;
    type HO = host_output::RegisterReport;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct HandshakeWorkflow;

impl HostEngine for HandshakeWorkflow {
    type HI = host_input::Handshake;
    type EI = input::Empty;
    type EO = output::ReturnHandshake;
    type HO = host_output::Handshake;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct RegisterNotificationWorkflow;

impl HostEngine for RegisterNotificationWorkflow {
    type HI = host_input::RegisterNotification;
    type EI = SodiumCiphertext;
    type EO = output::Empty;
    type HO = host_output::RegisterNotification;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct GetStateWorkflow;

impl HostEngine for GetStateWorkflow {
    type HI = host_input::GetState;
    type EI = SodiumCiphertext;
    type EO = output::ReturnState;
    type HO = host_output::GetState;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct InsertCiphertextWorkflow;

impl HostEngine for InsertCiphertextWorkflow {
    type HI = host_input::InsertCiphertext;
    type EI = input::InsertCiphertext;
    type EO = output::ReturnNotifyState;
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

pub struct GetEncryptionKeyWorkflow;

impl HostEngine for GetEncryptionKeyWorkflow {
    type HI = host_input::GetEncryptionKey;
    type EI = input::Empty;
    type EO = output::ReturnEncryptionKey;
    type HO = host_output::ReturnEncryptionKey;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct BackupPathSecretAllWorkflow;

impl HostEngine for BackupPathSecretAllWorkflow {
    type HI = host_input::BackupPathSecretAll;
    type EI = input::Empty;
    type EO = output::Empty;
    type HO = host_output::BackupPathSecretAll;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub struct RecoverPathSecretAllWorkflow;

impl HostEngine for RecoverPathSecretAllWorkflow {
    type HI = host_input::RecoverPathSecretAll;
    type EI = input::Empty;
    type EO = output::Empty;
    type HO = host_output::RecoverPathSecretAll;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
}

pub mod host_input {
    use super::*;

    pub struct Command {
        ciphertext: SodiumCiphertext,
        signer: Address,
        gas: u64,
        ecall_cmd: u32,
    }

    impl Command {
        pub fn new(
            ciphertext: SodiumCiphertext,
            signer: Address,
            gas: u64,
            ecall_cmd: u32,
        ) -> Self {
            Command {
                ciphertext,
                signer,
                gas,
                ecall_cmd,
            }
        }
    }

    impl HostInput for Command {
        type EcallInput = SodiumCiphertext;
        type HostOutput = host_output::Command;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let host_output = host_output::Command::new(self.signer, self.gas);

            Ok((self.ciphertext, host_output))
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
        type EcallInput = input::Empty;
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
        type EcallInput = input::Empty;
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
        type EcallInput = input::Empty;
        type HostOutput = host_output::Handshake;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let host_output = host_output::Handshake::new(self.signer, self.gas);

            Ok((Self::EcallInput::default(), host_output))
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
        type EcallInput = SodiumCiphertext;
        type HostOutput = host_output::RegisterNotification;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
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
        type EcallInput = SodiumCiphertext;
        type HostOutput = host_output::GetState;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            Ok((self.ciphertext, Self::HostOutput::new()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct InsertCiphertext {
        ciphertext: Ciphertext,
        state_counter: StateCounter,
        ecall_cmd: u32,
    }

    impl InsertCiphertext {
        pub fn new(ciphertext: Ciphertext, state_counter: StateCounter, ecall_cmd: u32) -> Self {
            InsertCiphertext {
                ciphertext,
                state_counter,
                ecall_cmd,
            }
        }
    }

    impl HostInput for InsertCiphertext {
        type EcallInput = input::InsertCiphertext;
        type HostOutput = host_output::InsertCiphertext;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.ciphertext, self.state_counter);

            Ok((ecall_input, Self::HostOutput::new()))
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
        type EcallInput = input::InsertHandshake;
        type HostOutput = host_output::InsertHandshake;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.handshake, self.state_counter);

            Ok((ecall_input, Self::HostOutput::default()))
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
        type EcallInput = input::Empty;
        type HostOutput = host_output::ReturnEncryptionKey;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            Ok((Self::EcallInput::default(), Self::HostOutput::new()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct BackupPathSecretAll {
        ecall_cmd: u32,
    }

    impl BackupPathSecretAll {
        pub fn new(ecall_cmd: u32) -> Self {
            BackupPathSecretAll { ecall_cmd }
        }
    }

    impl HostInput for BackupPathSecretAll {
        type EcallInput = input::Empty;
        type HostOutput = host_output::BackupPathSecretAll;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            Ok((Self::EcallInput::default(), Self::HostOutput::default()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct RecoverPathSecretAll {
        ecall_cmd: u32,
    }

    impl RecoverPathSecretAll {
        pub fn new(ecall_cmd: u32) -> Self {
            RecoverPathSecretAll { ecall_cmd }
        }
    }

    impl HostInput for RecoverPathSecretAll {
        type EcallInput = input::Empty;
        type HostOutput = host_output::RecoverPathSecretAll;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            Ok((Self::EcallInput::default(), Self::HostOutput::default()))
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
        pub ecall_output: Option<output::ReturnNotifyState>,
    }

    impl HostOutput for InsertCiphertext {
        type EcallOutput = output::ReturnNotifyState;

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

    pub struct ReturnEncryptionKey {
        pub ecall_output: Option<output::ReturnEncryptionKey>,
    }

    impl HostOutput for ReturnEncryptionKey {
        type EcallOutput = output::ReturnEncryptionKey;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
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
