use codec::{Decode, Encode};
use frame_common::{state_types::StateType, EcallInput, EcallOutput};
use frame_runtime::{ContextOps, RuntimeExecutor};

pub trait EnclaveEngine {
    type EI: EcallInput + Decode;
    type EO: EcallOutput + Encode;

    fn eval_policy(_ecall_input: &Self::EI) -> anyhow::Result<()> {
        Ok(())
    }

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        max_mem_size: usize,
    ) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone;
}
