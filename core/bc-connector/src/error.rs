use thiserror::Error;

pub type Result<T> = std::result::Result<T, HostError>;

#[derive(Error, Debug)]
pub enum HostError {
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