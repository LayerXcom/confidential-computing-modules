use std::marker::PhantomData;
use frame_host::engine::*;
use frame_common::{
    crypto::AccessRight,
    traits::*,
};
use anonify_common::{
    plugin_types::*,
    commands::*,
};
use web3::types::Address;
use crate::utils::StateInfo;

pub const OUTPUT_MAX_LEN: usize = 2048;

pub struct InstructionWorkflow<S: State, C: CallNameConverter> {
    s: PhantomData<S>,
    c: PhantomData<C>,
}

impl<S: State, C: CallNameConverter> HostEngine for InstructionWorkflow<S, C> {
    type HI = host_input::Instruction<S, C>;
    type EI = input::Instruction;
    type EO = output::Instruction;
    type HO = host_output::Instruction;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = ENCRYPT_INSTRUCTION_CMD;
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


pub mod host_input {
    use super::*;

    pub struct Instruction<S: State, C: CallNameConverter> {
        state: S,
        call_name: String,
        access_right: AccessRight,
        signer: Address,
        gas: u64,
        phantom: PhantomData<C>
    }

    impl<S: State, C: CallNameConverter> Instruction<S, C> {
        pub fn new(
            state: S,
            call_name: String,
            access_right: AccessRight,
            signer: Address,
            gas: u64,
        ) -> Self {
            Instruction {
                state, call_name, access_right, signer, gas,
                phantom: PhantomData,
            }
        }
    }

    impl<S: State, C: CallNameConverter> HostInput for Instruction<S, C> {
        type EcallInput = input::Instruction;
        type HostOutput = host_output::Instruction;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let state_info = StateInfo::<_, C>::new(self.state, &self.call_name);
            let ecall_input = state_info.crate_input(self.access_right);
            let host_output = host_output::Instruction::new(self.signer, self.gas);

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
}

pub mod host_output {
    use super::*;

    pub struct Instruction {
        pub signer: Address,
        pub gas: u64,
        pub ecall_output: Option<output::Instruction>,
    }

    impl HostOutput for Instruction {
        type EcallOutput = output::Instruction;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
            self.ecall_output = Some(output);

            Ok(self)
        }
    }

    impl Instruction {
        pub fn new(signer: Address, gas: u64) -> Self {
            Instruction {
                signer,
                gas,
                ecall_output: None,
            }
        }
    }

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
                ecall_output: None
            }
        }
    }

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
            JoinGroup {
                signer,
                gas,
                ecall_output: None
            }
        }
    }
}

