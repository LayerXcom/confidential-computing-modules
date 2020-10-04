use thiserror::Error;

pub type Result<T> = std::result::Result<T, ServerError>;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("{0}")]
    ModuleError(#[from] anonify_eth_driver::HostError),
    #[error("{0}")]
    FrameError(#[from] frame_host::Error),
    #[error("{0}")]
    Ed25519Error(#[from] ed25519_dalek::SignatureError),
}

impl actix_web::error::ResponseError for ServerError {}
