use frame_common::{state_types::StateType, EcallInput, EcallOutput};
use frame_runtime::{ContextOps, RuntimeExecutor};
use serde::{de::DeserializeOwned, Serialize};

pub trait StateRuntimeEnclaveEngine: Sized + Default {
    type EI: EcallInput + DeserializeOwned + Default;
    type EO: EcallOutput + Serialize + Default;

    fn new<C>(_ecall_input: Self::EI, _enclave_context: &C) -> anyhow::Result<Self>
    where
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self::default())
    }

    /// Evaluate policies like authentication and idempotency
    fn eval_policy(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Handler for state transition runtime
    fn handle<R, C>(self, _enclave_context: &C, _max_mem_size: usize) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self::EO::default())
    }
}
