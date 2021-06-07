use frame_common::{EnclaveInput, EnclaveOutput};
use frame_runtime::ConfigGetter;
use serde::{de::DeserializeOwned, Serialize};

pub trait BasicEnclaveUseCase: Sized + Default {
    type EI: EnclaveInput + DeserializeOwned + Default;
    type EO: EnclaveOutput + Serialize + Default;

    fn new<C>(_ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ConfigGetter,
    {
        Ok(Self::default())
    }

    /// Handler for basic engine
    fn handle<C>(self, _enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter,
    {
        Ok(Self::EO::default())
    }
}
