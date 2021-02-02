use thiserror::Error;

pub type Result<T> = std::result::Result<T, ServerError>;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("{0}")]
    AnyhowError(#[from] anyhow::Error),

    #[error("{0}")]
    KeyVaultHostError(#[from] key_vault_host::KeyVaultHostError),
}

impl actix_web::error::ResponseError for ServerError {}
