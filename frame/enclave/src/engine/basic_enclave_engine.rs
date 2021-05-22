use frame_common::{state_types::StateType, EcallInput, EcallOutput};
use frame_runtime::{ConfigGetter, ContextOps, RuntimeExecutor};
use serde::{de::DeserializeOwned, Serialize};

pub trait BasicEnclaveEngine: Sized + Default {
    type EI: EcallInput + DeserializeOwned + Default;
    type EO: EcallOutput + Serialize + Default;

    fn decrypt<C>(_ciphertext: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
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
