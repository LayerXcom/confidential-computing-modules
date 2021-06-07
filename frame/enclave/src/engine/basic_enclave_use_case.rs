use anyhow::anyhow;
use bincode::Options;
use frame_common::{EnclaveInput, EnclaveOutput};
use frame_runtime::ConfigGetter;
use log::error;
use serde::{de::DeserializeOwned, Serialize};
use std::{format, ptr, vec::Vec};

pub trait BasicEnclaveUseCase: Sized {
    type EI: EnclaveInput + DeserializeOwned + Default;
    type EO: EnclaveOutput + Serialize;

    fn run<C>(ecall_input: Self::EI, enclave_context: &C) -> anyhow::Result<Self::EO>
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
        let input = unsafe { std::slice::from_raw_parts_mut(input_buf, input_len) };
        let res = unsafe {
            match Self::start_use_case(input, enclave_context, ecall_max_size) {
                Ok(out) => out,
                Err(e) => {
                    error!("Error in enclave (ecall_entry_point): {:?}", e);
                    return frame_types::EnclaveStatus::error();
                }
            }
        };

        let res_len = res.len();
        *output_len = res_len;

        if res_len > ecall_max_size {
            error!(
                "Result buffer length is over ecall_max_size: ecall_max_size={}, res_len={}",
                ecall_max_size, res_len
            );
            return frame_types::EnclaveStatus::error();
        }
        unsafe {
            ptr::copy_nonoverlapping(res.as_ptr(), output_buf, res_len);
        }

        frame_types::EnclaveStatus::success()
    }

    fn start_use_case<C>(
        input_payload: &[u8],
        enclave_context: &C,
        ecall_max_size: usize,
    ) -> anyhow::Result<Vec<u8>>
    where
        C: ConfigGetter,
    {
        let res = {
            let ecall_input = bincode::DefaultOptions::new()
                .with_limit(ecall_max_size as u64)
                .deserialize(&input_payload[..])
                .map_err(|e| anyhow!("{:?}", e))?;

            Self::run(ecall_input, enclave_context)?
        };

        bincode::serialize(&res).map_err(Into::into)
    }
}
