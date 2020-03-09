use std::vec::Vec;
use super::DhPubKey;

#[derive(Debug, Clone)]
pub struct EciesCiphertext {
    ephemeral_public_key: DhPubKey,
    ciphertext: Vec<u8>,
}
