use crate::context::AnonifyEnclaveContext;

pub mod enclave_key;
pub mod executor;
pub mod plaintext;
pub mod treekem;

#[derive(Clone, Debug)]
pub struct ContextWithCmdCipherPaddingSize<'c> {
    pub ctx: &'c AnonifyEnclaveContext,

    /// Padding size (in bytes) of encrypted command written to block chain
    /// (to avoid guessing plain text from cipher size).
    pub cmd_cipher_padding_size: usize,
}
