use crate::error::{FrameHostError, Result};
use frame_common::{EcallInput, EcallOutput};
use frame_types::EnclaveStatus;
use serde::{de::DeserializeOwned, Serialize};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};

extern "C" {
    fn ecall_entry_point(
        eid: sgx_enclave_id_t,
        retval: *mut EnclaveStatus,
        cmd: u32,
        in_buf: *mut u8,
        in_len: usize,
        out_buf: *mut u8,
        out_max: usize,
        out_len: &mut usize,
    ) -> sgx_status_t;
}

pub struct EnclaveConnector {
    eid: sgx_enclave_id_t,
    output_max_len: usize,
}

impl EnclaveConnector {
    pub fn new(eid: sgx_enclave_id_t, output_max_len: usize) -> Self {
        EnclaveConnector {
            eid,
            output_max_len,
        }
    }

    pub fn invoke_ecall<E, D>(&self, cmd: u32, input: E) -> Result<D>
    where
        E: Serialize + EcallInput,
        D: DeserializeOwned + EcallOutput,
    {
        let input_payload = bincode::serialize(&input)?;
        let st3 = std::time::SystemTime::now();
        println!("########## st3: {:?}", st3);
        let result = self.inner_invoke_ecall(cmd, input_payload)?;
        let st8 = std::time::SystemTime::now();
        println!("########## st8: {:?}", st8);
        bincode::deserialize(&result[..]).map_err(Into::into)
    }

    fn inner_invoke_ecall(&self, cmd: u32, mut input: Vec<u8>) -> Result<Vec<u8>> {
        let input_ptr = input.as_mut_ptr();
        let input_len = input.len();
        let output_max = self.output_max_len;
        let mut output_len = output_max;
        let mut output_buf = Vec::with_capacity(output_max);
        let output_ptr = output_buf.as_mut_ptr();

        let mut ret = EnclaveStatus::default();

        let st4 = std::time::SystemTime::now();
        println!("########## st4: {:?}", st4);
        let status = unsafe {
            ecall_entry_point(
                self.eid,
                &mut ret,
                cmd,
                input_ptr,
                input_len,
                output_ptr,
                output_max,
                &mut output_len,
            )
        };
        let st7 = std::time::SystemTime::now();
        println!("########## st7: {:?}", st7);

        if status != sgx_status_t::SGX_SUCCESS {
            return Err(FrameHostError::SgxStatus {
                status,
                function: "ecall_entry_point(SgxStatus)",
                cmd,
            });
        }
        if ret.is_err() {
            return Err(FrameHostError::EnclaveError {
                status: ret,
                function: "ecall_entry_point",
                cmd,
            });
        }
        assert!(output_len < output_max);

        unsafe {
            output_buf.set_len(output_len);
        }

        Ok(output_buf)
    }
}
