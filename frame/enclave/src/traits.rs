use codec::Encode;
use frame_common::{
    EcallOutput,
    state_types::StateType,
};
use frame_runtime::{RuntimeExecutor, ContextOps};

pub trait EcallHandler {
    type O: EcallOutput + Encode;

    fn handle<R, C>(
        self,
        enclave_context: &C,
        max_mem_size: usize,
    ) -> anyhow::Result<Self::O>
    where
        R: RuntimeExecutor<C, S=StateType>,
        C: ContextOps<S=StateType> + Clone;
}

