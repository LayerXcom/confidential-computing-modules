use frame_common::{EnclaveInput, EnclaveOutput};
use frame_runtime::ConfigGetter;
use serde::{de::DeserializeOwned, Serialize};

pub trait BasicEnclaveUseCase: Sized {
    type EI: EnclaveInput + DeserializeOwned + Default;
    type EO: EnclaveOutput + Serialize;

    fn run<C>(ecall_input: Self::EI, enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter;
}
