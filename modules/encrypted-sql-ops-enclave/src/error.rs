//! Error and Result types.

use thiserror::Error;

/// The result type in this crate.
pub type Result<T> = std::result::Result<T, EnclaveError>;

/// The error type in this crate.
#[derive(Error, Debug)]
pub enum EnclaveError {
    /// Error while decrypting data into plain text.
    #[error("decrypted block is {decrypted_size} bytes, while expected to be 16 bytes ({plain_size}-byte sized type with 16-byte padding))")]
    DecryptError {
        /// data length after decryption
        decrypted_size: usize,
        /// expected length of plain text
        plain_size: usize,
    },
}
