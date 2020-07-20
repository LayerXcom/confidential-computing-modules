use thiserror::Error;
use frame_types::EnclaveStatus;
use sgx_types::sgx_status_t;

pub type Result<T> = std::result::Result<T, FrameHostError>;

#[derive(Error, Debug)]
pub enum FrameHostError {
    #[error("Error: {0}")]
    Error(#[from] anyhow::Error),
    #[error("SGX ecall failed function: {function:?}, status: {status:?}, command: {cmd:?}")]
    SgxStatus {
        status: sgx_status_t,
        function: &'static str,
        cmd: u32,
    },
    #[error("Enclave ecall failed function: {function:?}, status: {status:?}, command: {cmd:?}")]
    EnclaveError {
        status: EnclaveStatus,
        function: &'static str,
        cmd: u32,
    },
    #[error("Codec error: {0}")]
    CodecError(#[from] codec::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
