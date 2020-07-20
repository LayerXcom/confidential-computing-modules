use crate::error::Result;
use crate::ecalls::EnclaveConnector;
use sgx_types::sgx_enclave_id_t;
use frame_common::{EcallInput, EcallOutput};
use serde::de::DeserializeOwned;
use codec::{Encode, Decode};

pub trait WorkflowEngine {
    type HI: HostInput<EcallInput = Self::EI>;
    type EI: EcallInput + Encode;
    type EO: EcallOutput + Decode;
    type HO: HostOutput<EcallOutput = Self::EO>;

    fn exec(input: Self::HI, eid: sgx_enclave_id_t, output_max_len: usize, cmd: u32) -> anyhow::Result<()> {
        let ecall_input = input.try_into_ecall_input()?;
        let ecall_output = EnclaveConnector::new(eid, output_max_len)
            .invoke_ecall::<Self::EI, Self::EO>(cmd, ecall_input)?;

        Self::HO::from_ecall_output(ecall_output)?
            .emit()
    }
}

pub trait HostInput: Sized + DeserializeOwned {
    type EcallInput: EcallInput;

    fn from_slice_json(s: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(s).map_err(Into::into)
    }

    fn from_str_json(s: &str) -> anyhow::Result<Self> {
        serde_json::from_str(s).map_err(Into::into)
    }

    fn try_into_ecall_input(self) -> anyhow::Result<Self::EcallInput>;
}

pub trait HostOutput: Sized {
    type EcallOutput: EcallOutput;

    fn from_ecall_output(output: Self::EcallOutput) -> anyhow::Result<Self>;

    fn emit(self) -> anyhow::Result<()>;
}
