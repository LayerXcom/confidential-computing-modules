use anyhow::anyhow;
use frame_common::state_types::UserCounter;
use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, EnclaveError>;

#[derive(Error, Debug)]
pub enum EnclaveError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    EnvVarError(#[from] std::env::VarError),
    #[error("Secp256k1 error: {0:?}")]
    Secp256k1Error(secp256k1::Error),
    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),
    #[error("Frame mra-tls error: {0}")]
    FrameMraTLSError(#[from] frame_mra_tls::MraTLSError),
    #[error("Bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("Received UserCounter is {received:?}, but expected is {expected:?}")]
    InvalidUserCounter {
        received: UserCounter,
        expected: UserCounter,
    },
     #[error("Enclave Decryption Key is not set")]
    NotSetEnclaveDecKeyError,
}

impl From<sgx_types::sgx_status_t> for EnclaveError {
    fn from(err: sgx_types::sgx_status_t) -> Self {
        anyhow!("Sgx error: {:?}", err).into()
    }
}

impl From<secp256k1::Error> for EnclaveError {
    fn from(err: secp256k1::Error) -> Self {
        anyhow!("Secp256k1 error: {:?}", err).into()
    }
}
