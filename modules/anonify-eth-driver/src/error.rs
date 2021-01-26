use thiserror::Error;

pub type Result<T> = std::result::Result<T, HostError>;

#[derive(Error, Debug)]
pub enum HostError {
    #[error("Error: {0}")]
    Error(#[from] anyhow::Error),
    #[error("Contract address have not been set.")]
    AddressNotSet,
    #[error("Event watcher have not been set.")]
    EventWatcherNotSet,
    #[error("Ecall output is not set. An error would have occurred in the enclave")]
    EcallOutputNotSet,
    #[error("Failed unlock the account")]
    UnlockError,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Web3 error: {0}")]
    Web3Error(#[from] web3::Error),
    #[error("Web3 contract error: {0}")]
    Web3ContractError(#[from] web3::contract::Error),
    #[error("Web3 contract deploy error: {0}")]
    Web3ContractDeployError(#[from] web3::contract::deploy::Error),
    #[error("Ethabi error: {0}")]
    EthabiError(#[from] ethabi::Error),
    #[error("Frame host error: {0}")]
    FrameHostError(#[from] frame_host::Error),
    #[error("Serde json error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
}
