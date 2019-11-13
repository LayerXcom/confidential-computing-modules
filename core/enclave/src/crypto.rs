use anonify_common::types::Ciphertext;

/// The size of the symmetric 256 bit key we use for encryption (in bytes).
pub const SYMMETRIC_KEY_SIZE: usize = 256 / 8;
/// symmetric key we use for encryption.
pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];

// Symmetric encryption scheme for state.
pub trait AES256GCM {
    fn encrypt(&self, key: &SymmetricKey) -> Ciphertext;

    fn decrypt(ciphertext: Ciphertext, key: &SymmetricKey) -> Self;
}

// TODO: User's Signature Verification

// TODO: Enclave's signature generation
