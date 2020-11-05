use thiserror::Error;
use std::io;

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    WalletError(#[from] anonify_wallet::Error),
    #[error("{0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("{0}")]
    AnyhowError(#[from] anyhow::Error),
}
