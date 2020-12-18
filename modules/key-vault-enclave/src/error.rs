use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyVaultEnclaveError {
    #[error("Anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),
}