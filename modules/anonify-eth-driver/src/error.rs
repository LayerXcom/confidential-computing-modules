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
    #[error("Ethabi error: {0}")]
    EthabiError(#[from] ethabi::Error),
    #[error("Codec error: {0}")]
    CodecError(#[from] codec::Error),
    #[error("Frame host error: {0}")]
    FrameHostError(#[from] frame_host::Error),
}
