use crate::ecalls::EnclaveConnector;
use frame_common::{EnclaveInput, EnclaveOutput};
use serde::{de::DeserializeOwned, Serialize};

use sgx_types::sgx_enclave_id_t;

pub trait EcallController {
    type HI: HostInput<EnclaveInput = Self::EI, HostOutput = Self::HO>;
    type EI: EnclaveInput + Serialize;
    type EO: EnclaveOutput + DeserializeOwned;
    type HO: HostOutput<EnclaveOutput = Self::EO>;
    const ECALL_MAX_SIZE: usize;

    fn exec(input: Self::HI, eid: sgx_enclave_id_t) -> anyhow::Result<Self::HO> {
        let ecall_cmd = input.ecall_cmd();
        let (ecall_input, host_output) = input.apply()?;
        let ecall_output = EnclaveConnector::new(eid, Self::ECALL_MAX_SIZE)
            .invoke_ecall::<Self::EI, Self::EO>(ecall_cmd, ecall_input)?;

        host_output.set_ecall_output(ecall_output)
    }
}

pub trait HostInput: Sized {
    type EnclaveInput: EnclaveInput;
    type HostOutput: HostOutput;

    fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)>;

    fn ecall_cmd(&self) -> u32;
}

pub trait HostOutput: Sized {
    type EnclaveOutput: EnclaveOutput;

    fn set_ecall_output(self, _output: Self::EnclaveOutput) -> anyhow::Result<Self> {
        Ok(self)
    }
}
