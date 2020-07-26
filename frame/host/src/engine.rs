use crate::ecalls::EnclaveConnector;
use sgx_types::sgx_enclave_id_t;
use frame_common::{EcallInput, EcallOutput};
use serde::de::DeserializeOwned;
use codec::{Encode, Decode};

pub trait HostEngine {
    type HI: HostInput<EcallInput = Self::EI, HostOutput = Self::HO>;
    type EI: EcallInput + Encode;
    type EO: EcallOutput + Decode;
    type HO: HostOutput<EcallOutput = Self::EO>;
    const OUTPUT_MAX_LEN: usize;
    const CMD: u32;

    fn exec(input: Self::HI, eid: sgx_enclave_id_t) -> anyhow::Result<Self::HO> {
        let (ecall_input, host_output) = input.apply()?;
        let ecall_output = EnclaveConnector::new(eid, Self::OUTPUT_MAX_LEN)
            .invoke_ecall::<Self::EI, Self::EO>(Self::CMD, ecall_input)?;

        host_output
            .set_ecall_output(ecall_output)
    }
}

pub trait HostInput: Sized {
    type EcallInput: EcallInput;
    type HostOutput: HostOutput;

    fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)>;
}

pub trait HostOutput: Sized {
    type EcallOutput: EcallOutput;

    fn set_ecall_output(self, output: Self::EcallOutput) -> anyhow::Result<Self>;

    // TODO
    // fn emit(self) -> anyhow::Result<String>;
}
