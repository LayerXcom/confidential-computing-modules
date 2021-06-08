use crate::ecalls::EnclaveConnector;
use frame_common::{EnclaveInput, EnclaveOutput};
use serde::{de::DeserializeOwned, Serialize};

use sgx_types::sgx_enclave_id_t;

pub trait EcallController {
    type HI: HostInput;
    type EI: EnclaveInput + Serialize;
    type EO: EnclaveOutput + DeserializeOwned;
    type HO: HostOutput;

    /// Max acceptable size of enclave input.
    /// This is to avoid DoS attack by too large input.
    const EI_MAX_SIZE: usize;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI>;

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO>;

    fn run(input: Self::HI, ecall_cmd: u32, eid: sgx_enclave_id_t) -> anyhow::Result<Self::HO> {
        let enclave_input = Self::translate_input(input)?;

        let enclave_output = EnclaveConnector::new(eid, Self::EI_MAX_SIZE)
            .invoke_ecall::<Self::EI, Self::EO>(ecall_cmd, enclave_input)?;

        Self::translate_output(enclave_output)
    }
}

pub trait HostInput: Sized {}

pub trait HostOutput: Sized {}
