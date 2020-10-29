use crate::utils::StateInfo;
use anonify_io_types::*;
use config::constants::*;
use frame_common::{
    crypto::{Ciphertext, ExportHandshake},
    state_types::MemId,
    traits::*,
};
use frame_host::engine::*;
use std::marker::PhantomData;
use web3::types::Address;

pub const OUTPUT_MAX_LEN: usize = 2048;

pub struct CommandWorkflow<S: State, C: CallNameConverter, AP: AccessPolicy> {
    s: PhantomData<S>,
    c: PhantomData<C>,
    ap: PhantomData<AP>,
}

impl<S: State, C: CallNameConverter, AP: AccessPolicy> HostEngine
    for CommandWorkflow<S, C, AP>
{
    type HI = host_input::Command<S, C, AP>;
    type EI = input::Command<AP>;
    type EO = output::Command;
    type HO = host_output::Command;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = ENCRYPT_COMMAND_CMD;
}

pub struct JoinGroupWorkflow;

impl HostEngine for JoinGroupWorkflow {
    type HI = host_input::JoinGroup;
    type EI = input::CallJoinGroup;
    type EO = output::ReturnJoinGroup;
    type HO = host_output::JoinGroup;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = CALL_JOIN_GROUP_CMD;
}

pub struct HandshakeWorkflow;

impl HostEngine for HandshakeWorkflow {
    type HI = host_input::Handshake;
    type EI = input::CallHandshake;
    type EO = output::ReturnHandshake;
    type HO = host_output::Handshake;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = CALL_HANDSHAKE_CMD;
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
    const CMD: u32 = REGISTER_NOTIFICATION_CMD;
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
    const CMD: u32 = GET_STATE_CMD;
}

pub struct InsertCiphertextWorkflow;

impl HostEngine for InsertCiphertextWorkflow {
    type HI = host_input::InsertCiphertext;
    type EI = input::InsertCiphertext;
    type EO = output::ReturnUpdatedState;
    type HO = host_output::InsertCiphertext;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = INSERT_CIPHERTEXT_CMD;
}

pub struct InsertHandshakeWorkflow;

impl HostEngine for InsertHandshakeWorkflow {
    type HI = host_input::InsertHandshake;
    type EI = input::InsertHandshake;
    type EO = output::Empty;
    type HO = host_output::InsertHandshake;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = INSERT_HANDSHAKE_CMD;
}

pub mod host_input {
    use super::*;

    pub struct Command<S: State, C: CallNameConverter, AP: AccessPolicy> {
        state: S,
        call_name: String,
        access_policy: AP,
        signer: Address,
        gas: u64,
        phantom: PhantomData<C>,
    }

    impl<S: State, C: CallNameConverter, AP: AccessPolicy> Command<S, C, AP> {
        pub fn new(
            state: S,
            call_name: String,
            access_policy: AP,
            signer: Address,
            gas: u64,
        ) -> Self {
            Command {
                state,
                call_name,
                access_policy,
                signer,
                gas,
                phantom: PhantomData,
            }
        }
    }

    impl<S: State, C: CallNameConverter, AP: AccessPolicy> HostInput for Command<S, C, AP> {
        type EcallInput = input::Command<AP>;
        type HostOutput = host_output::Command;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let state_info = StateInfo::<_, C>::new(self.state, &self.call_name);
            let ecall_input = state_info.crate_input(self.access_policy);
            let host_output = host_output::Command::new(self.signer, self.gas);

            Ok((ecall_input, host_output))
        }
    }

    pub struct JoinGroup {
        signer: Address,
        gas: u64,
    }

    impl JoinGroup {
        pub fn new(signer: Address, gas: u64) -> Self {
            JoinGroup { signer, gas }
        }
    }

    impl HostInput for JoinGroup {
        type EcallInput = input::CallJoinGroup;
        type HostOutput = host_output::JoinGroup;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let host_output = host_output::JoinGroup::new(self.signer, self.gas);

            Ok((Self::EcallInput::default(), host_output))
        }
    }

    pub struct Handshake {
        signer: Address,
        gas: u64,
    }

    impl Handshake {
        pub fn new(signer: Address, gas: u64) -> Self {
            Handshake { signer, gas }
        }
    }

    impl HostInput for Handshake {
        type EcallInput = input::CallHandshake;
        type HostOutput = host_output::Handshake;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let host_output = host_output::Handshake::new(self.signer, self.gas);

            Ok((Self::EcallInput::default(), host_output))
        }
    }

    pub struct RegisterNotification<AP: AccessPolicy> {
        access_policy: AP,
    }

    impl<AP: AccessPolicy> RegisterNotification<AP> {
        pub fn new(access_policy: AP) -> Self {
            RegisterNotification { access_policy }
        }
    }

    impl<AP: AccessPolicy> HostInput for RegisterNotification<AP> {
        type EcallInput = input::RegisterNotification<AP>;
        type HostOutput = host_output::RegisterNotification;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.access_policy);

            Ok((ecall_input, Self::HostOutput::default()))
        }
    }

    pub struct GetState<AP: AccessPolicy> {
        access_policy: AP,
        mem_id: MemId,
    }

    impl<AP: AccessPolicy> GetState<AP> {
        pub fn new(access_policy: AP, mem_id: MemId) -> Self {
            GetState {
                access_policy,
                mem_id,
            }
        }
    }

    impl<AP: AccessPolicy> HostInput for GetState<AP> {
        type EcallInput = input::GetState<AP>;
        type HostOutput = host_output::GetState;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.access_policy, self.mem_id);

            Ok((ecall_input, Self::HostOutput::new()))
        }
    }

    pub struct InsertCiphertext {
        ciphertext: Ciphertext,
    }

    impl InsertCiphertext {
        pub fn new(ciphertext: Ciphertext) -> Self {
            InsertCiphertext { ciphertext }
        }
    }

    impl HostInput for InsertCiphertext {
        type EcallInput = input::InsertCiphertext;
        type HostOutput = host_output::InsertCiphertext;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.ciphertext);

            Ok((ecall_input, Self::HostOutput::new()))
        }
    }

    pub struct InsertHandshake {
        handshake: ExportHandshake,
    }

    impl InsertHandshake {
        pub fn new(handshake: ExportHandshake) -> Self {
            InsertHandshake { handshake }
        }
    }

    impl HostInput for InsertHandshake {
        type EcallInput = input::InsertHandshake;
        type HostOutput = host_output::InsertHandshake;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.handshake);

            Ok((ecall_input, Self::HostOutput::default()))
        }
    }
}

pub mod host_output {
    use super::*;

    #[derive(Debug)]
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
}
