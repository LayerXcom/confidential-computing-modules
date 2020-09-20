use std::{fmt, io};

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Debug)]
pub enum ClientError {
    IoError(io::Error),
    WalletError(anonify_wallet::Error),
    ReqwestError(reqwest::Error),
}

impl From<io::Error> for ClientError {
    fn from(err: io::Error) -> Self {
        ClientError::IoError(err)
    }
}

impl From<anonify_wallet::Error> for ClientError {
    fn from(err: anonify_wallet::Error) -> Self {
        ClientError::WalletError(err)
    }
}

impl From<reqwest::Error> for ClientError {
    fn from(err: reqwest::Error) -> Self {
        ClientError::ReqwestError(err)
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ClientError::IoError(ref err) => write!(f, "I/O error: {}", err),
            ClientError::WalletError(ref err) => write!(f, "Wallet error: {}", err),
            ClientError::ReqwestError(ref err) => write!(f, "Reqwest error: {}", err),
        }
    }
}
