use thiserror::Error;

pub type Result<T> = std::result::Result<T, ServerError>;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("{0}")]
    AnyhowError(#[from] anyhow::Error),
}

impl actix_web::error::ResponseError for ServerError {}
