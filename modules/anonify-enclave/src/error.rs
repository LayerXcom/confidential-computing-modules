use anyhow::anyhow;
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

    #[error("Codec error: {0:?}")]
    CodecError(codec::Error),

    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),

    #[error("Frame mra-tls error: {0}")]
    FrameMraTLSError(#[from] frame_mra_tls::MraTLSError),
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

impl From<codec::Error> for EnclaveError {
    fn from(err: codec::Error) -> Self {
        anyhow!("Codec error: {:?}", err).into()
    }
}
