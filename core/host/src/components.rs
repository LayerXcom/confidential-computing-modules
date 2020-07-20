use std::marker::PhantomData;
use frame_host::engine::*;
use frame_common::{CallNameConverter, State};
use anonify_common::plugin_types::*;

pub struct Instruction;

impl WorkflowEngine for Instruction {
    type HI = host_input::Instruction;
    type EI = input::Instruction;
    type EO = output::Instruction;
    type HO = host_output::Instruction;
}

pub mod host_input {
    use super::*;

    pub struct Instruction<'a, S: State, C: CallNameConverter> {
        state: S,
        call_name: &'a str,
        access_right: AccessRight,
        phantom: PhantomData<C>
    }

    impl<S: State, C: CallNameConverter> Instruction<'_, S, C> {
        pub fn new(state: S, call_name: &str, access_right: AccessRight) -> Self {
            Instruction { state, call_name, access_right }
        }
    }

    impl<S: State, C: CallNameConverter>  HostInput for Instruction<'_, S, C> {
        type EcallInput = input::Instruction;

        fn into_ecall_input(self) -> anyhow::Result<Self::EcallInput> {
            let state_info = StateInfo::<_, C>::new(self.state, self.call_name);
            Ok(state_info.crate_input(self.access_right))
        }
    }
}

pub mod host_output {
    use super::*;

    pub struct Instruction {
        pub contract: Option<>,
        pub from: Address,
        pub ciphertext: Vec<u8>,
        pub enclave_sig: Vec<u8>,
        pub msg: [u8; 32],
        pub gas: u64,
    }

    impl HostOutput for Instruction {
        type EcallOutput = output::Instruction;

        fn from_ecall_output(output: Self::EcallOutput) -> anyhow::Result<Self> {
            unimplemented!();
        }

        fn emit(self) -> anyhow::Result<String> {
            unimplemented!();
        }
    }
}

