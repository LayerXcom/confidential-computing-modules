use std::marker::PhantomData;
use frame_host::engine::*;
use frame_common::{CallNameConverter, State};
use anonify_common::plugin_types::*;
use web3::types::Address;

pub const OUTPUT_MAX_LEN: usize = 2048;

pub struct InstructionWorkflow;

impl WorkflowEngine for InstructionWorkflow {
    type HI = host_input::Instruction;
    type EI = input::Instruction;
    type EO = output::Instruction;
    type HO = host_output::Instruction;
    const OUTPUT_MAX_LEN = OUTPUT_MAX_LEN;
    const CMD = ENCRYPT_INSTRUCTION_CMD;
}

pub mod host_input {
    use super::*;

    pub struct Instruction<'a, S: State, C: CallNameConverter> {
        state: S,
        call_name: &'a str,
        access_right: AccessRight,
        signer: Address,
        gas: u64,
        phantom: PhantomData<C>
    }

    impl<S: State, C: CallNameConverter> Instruction<'_, S, C> {
        pub fn new(
            state: S,
            call_name: &str,
            access_right: AccessRight,
            signer: Address,
            gas: u64,
        ) -> Self {
            Instruction { state, call_name, access_right, signer, gas }
        }
    }

    impl<S: State, C: CallNameConverter>  HostInput for Instruction<'_, S, C> {
        type EcallInput = input::Instruction;
        type HostOutput = host_output::Instruction;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let state_info = StateInfo::<_, C>::new(self.state, self.call_name);
            let ecall_input = state_info.crate_input(self.access_right);
            let host_output = host_output::Instruction::new(signer, gas);

            Ok((ecall_input, host_output))
        }
    }
}

pub mod host_output {
    use super::*;

    pub struct Instruction {
        pub signer: Address,
        pub gas: u64,
        pub ciphertext: Option<Vec<u8>>,
        pub enclave_sig: Option<[u8; 64]>,
        pub msg: Option<[u8; 32]>,
    }

    impl HostOutput for Instruction {
        type EcallOutput = output::Instruction;

        fn set_ecall_output(mut self, output: Self::EcallOutput) -> anyhow::Result<Self> {
            self.ciphertext = Some(output.encode_ciphertext());
            self.enclave_sig = Some(output.encode_enclave_sig());
            self.msg = Some(output.msg_as_array());

            self
        }
    }

    impl Instruction {
        pub fn new(signer: Address. gas: u64) -> Self {
            Instruction {
                signer,
                gas,
                ciphertext: None,
                enclave_sig: None,
                msg: None,
            }
        }
    }
}

