use frame_common::{EnclaveInput, EnclaveOutput};
use frame_runtime::ConfigGetter;
use log::error;
use serde::{de::DeserializeOwned, Serialize};

use super::{mk_input_ecall_entry_point, mk_output_ecall_entry_point};

pub trait BasicEnclaveUseCase: Sized {
    type EI: EnclaveInput + DeserializeOwned + Default;
    type EO: EnclaveOutput + Serialize;

    fn run<C>(enclave_input: Self::EI, enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter;

    fn ecall_entry_point<C>(
        input_buf: *mut u8,
        input_len: usize,
        output_buf: *mut u8,
        ecall_max_size: usize,
        output_len: &mut usize,
        enclave_context: &C,
    ) -> frame_types::EnclaveStatus
    where
        C: ConfigGetter,
    {
        mk_input_ecall_entry_point(input_buf, input_len, ecall_max_size)
            .and_then(|enclave_input| {
                Self::run(enclave_input, enclave_context).and_then(|enclave_output| {
                    mk_output_ecall_entry_point(
                        enclave_output,
                        output_buf,
                        ecall_max_size,
                        output_len,
                    )
                })
            })
            .unwrap_or_else(|e| {
                error!("Error in enclave (ecall_entry_point): {:?}", e);
                frame_types::EnclaveStatus::error()
            })
    }
}
