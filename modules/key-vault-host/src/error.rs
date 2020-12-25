use thiserror::Error;

pub type Result<T> = std::result::Result<T, KeyVaultHostError>;

#[derive(Error, Debug)]
pub enum KeyVaultHostError {
    #[error("Error: {0}")]
    Error(#[from] anyhow::Error),
}
