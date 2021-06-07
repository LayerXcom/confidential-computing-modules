use frame_common::{EnclaveInput, EnclaveOutput};
use frame_runtime::ConfigGetter;
use serde::{de::DeserializeOwned, Serialize};

pub trait BasicEnclaveUseCase: Sized + Default {
    type EI: EnclaveInput + DeserializeOwned + Default;
    type EO: EnclaveOutput + Serialize;

    fn new<C>(_ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ConfigGetter;

    fn run<C>(self, _enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter;
}
