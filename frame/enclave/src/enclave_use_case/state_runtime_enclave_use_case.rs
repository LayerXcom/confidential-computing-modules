use frame_common::{state_types::StateType, EnclaveInput, EnclaveOutput};
use frame_runtime::ContextOps;
use log::error;
use serde::{de::DeserializeOwned, Serialize};

use super::{mk_input_ecall_entry_point, mk_output_ecall_entry_point};

pub trait StateRuntimeEnclaveUseCase<'c, C>: Sized
where
    C: ContextOps<S = StateType> + Clone,
{
    type EI: EnclaveInput + DeserializeOwned;
    type EO: EnclaveOutput + Serialize;

    fn new(enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self>;

    /// Evaluate policies like authentication and idempotency
    fn eval_policy(&self) -> anyhow::Result<()>;

    fn run(self) -> anyhow::Result<Self::EO>;

    fn ecall_entry_point(
        input_buf: *mut u8,
        input_len: usize,
        output_buf: *mut u8,
        ecall_max_size: usize,
        output_len: &mut usize,
        enclave_context: &'c C,
    ) -> frame_types::EnclaveStatus {
        mk_input_ecall_entry_point(input_buf, input_len, ecall_max_size)
            .and_then(|enclave_input| {
                Self::new(enclave_input, enclave_context).and_then(|slf| {
                    slf.run().and_then(|enclave_output| {
                        mk_output_ecall_entry_point(
                            enclave_output,
                            output_buf,
                            ecall_max_size,
                            output_len,
                        )
                    })
                })
            })
            .unwrap_or_else(|e| {
                error!("Error in enclave (ecall_entry_point): {:?}", e);
                frame_types::EnclaveStatus::error()
            })
    }
}
