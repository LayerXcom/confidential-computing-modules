use thiserror::Error;
use sgx_types::sgx_status_t;
use anonify_types::EnclaveStatus;

pub type Result<T> = std::result::Result<T, HostError>;

#[derive(Error, Debug)]
pub enum HostError {
    #[error("Error: {0}")]
    Error(#[from] anyhow::Error),
    #[error("SGX ecall failed function: {function:?}, status: {status:?}")]
    Sgx {
        status: sgx_status_t,
        function: &'static str,
        // command: u32,
    },
    #[error("Enclave ecall failed function: {function:?}, status: {status:?}")]
    Enclave {
        status: EnclaveStatus,
        function: &'static str,
        // command: u32,
    },
    #[error("Contract address have not been set.")]
    AddressNotSet,
    #[error("Event watcher have not been set.")]
    EventWatcherNotSet,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Web3 error: {0}")]
    Web3Error(#[from] web3::Error),
    #[error("Codec error: {0}")]
    CodecError(#[from] codec::Error),
}