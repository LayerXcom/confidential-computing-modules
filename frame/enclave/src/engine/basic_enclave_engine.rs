use frame_common::{EcallInput, EcallOutput};
use frame_runtime::ConfigGetter;
use serde::{de::DeserializeOwned, Serialize};

pub trait BasicEnclaveEngine: Sized + Default {
    type EI: EcallInput + DeserializeOwned + Default;
    type EO: EcallOutput + Serialize + Default;

    fn new<C>(_ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ConfigGetter,
    {
        Ok(Self::default())
    }

    /// Handler for basic engine
    fn handle<C>(_enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter,
    {
        Ok(Self::EO::default())
    }
}
