use codec::{Encode, Decode};
use frame_common::{
    EcallInput, EcallOutput,
    state_types::StateType,
};
use frame_runtime::{RuntimeExecutor, ContextOps};

pub trait EnclaveEngine {
    type EI: EcallInput + Decode;
    type EO: EcallOutput + Encode;

    fn is_accessible(ecall_input: Self::EI) -> bool {}

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        max_mem_size: usize,
    ) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone;
}
