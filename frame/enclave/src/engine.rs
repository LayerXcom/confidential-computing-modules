use codec::{Decode, Encode};
use frame_common::{state_types::StateType, EcallInput, EcallOutput};
use frame_runtime::{ConfigGetter, ContextOps, RuntimeExecutor};

pub trait EnclaveEngine {
    type EI: EcallInput + Decode;
    type EO: EcallOutput + Encode + Default;

    fn decrypt<C>(ciphertext: EciesCiphertext, enclave_context: &C) -> anyhow::Result<Self::EI>
    where
    C: ContextOps<S = StateType> + Clone {
        enclave_context.decrypt
    }

    /// Evaluate policies like authentication and idempotency
    fn eval_policy(_ecall_input: &Self::EI) -> anyhow::Result<()> {
        Ok(())
    }

    /// If the module have a state transition runtime, use this handler.
    fn handle<R, C>(
        _ecall_input: Self::EI,
        _enclave_context: &C,
        _max_mem_size: usize,
    ) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(Self::EO::default())
    }

    /// If the module doesn't have a state transition runtime, use this handler.
    fn handle_without_runtime<C>(_enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter,
    {
        Ok(Self::EO::default())
    }
}
