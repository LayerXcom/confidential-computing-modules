use std::{
    prelude::v1::Vec,
    io::{Write, Read},
};
use anonify_types::{Ciphertext};
use ring::aead::{self, Aad, BoundKey, Nonce, UnboundKey, AES_256_GCM};
use ed25519_dalek::{PublicKey, Signature};
use crate::{
    error::Result,
    state::{CurrentNonce, State, UserState},
};

/// The size of the symmetric 256 bit key we use for encryption in bytes.
pub const SYMMETRIC_KEY_SIZE: usize = 32;
/// symmetric key we use for encryption.
pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];

/// The size of initialization vector for AES-256-GCM.
pub const IV_SIZE: usize = 12;

/// Generating a random number inside the enclave.
pub fn rng_gen(rand: &mut [u8]) -> Result<()> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)?;
    Ok(())
}

/// Encryption with AES-256-GCM.
pub fn encrypt_aes_256_gcm(msg: Vec<u8>, key: &SymmetricKey) -> Result<Vec<u8>> {
    let mut iv = [0u8; IV_SIZE];
    rng_gen(&mut iv)?;

    let ub_key = UnboundKey::new(&AES_256_GCM, key)?;
    let nonce = Nonce::assume_unique_for_key(iv);
    let nonce_seq = OneNonceSequence::new(nonce);

    let mut s_key = aead::SealingKey::new(ub_key, nonce_seq);
    let mut data = msg;
    s_key.seal_in_place_append_tag(Aad::empty(), &mut data)?;
    data.extend_from_slice(&iv);

    Ok(data)
}

/// Decryption with AES-256-GCM.
pub fn decrypt_aes_256_gcm(cipheriv: Vec<u8>, key: &SymmetricKey) -> Result<Vec<u8>> {
    let ub_key = UnboundKey::new(&AES_256_GCM, key)?;
    let (ciphertext, iv) = cipheriv.split_at(cipheriv.len() - IV_SIZE);

    let nonce = Nonce::try_assume_unique_for_key(iv)?;
    let nonce_seq = OneNonceSequence::new(nonce);
    let mut o_key = aead::OpeningKey::new(ub_key, nonce_seq);

    let mut ciphertext = ciphertext.to_vec();
    o_key.open_in_place(Aad::empty(), &mut ciphertext)?;

    Ok(ciphertext)
}

/// A sequences of unique nonces.
/// See: https://briansmith.org/rustdoc/ring/aead/trait.NonceSequence.html
struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: aead::Nonce) -> Self {
        OneNonceSequence(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> std::result::Result<aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified).into()
    }
}

/// Trait for 256-bits hash functions
pub trait Hash256: Sized {
    fn hash(inp: &[u8]) -> Self;

    fn from_pubkey(pubkey: &PublicKey) -> Self;

    fn from_user_state<S: State>(user_state: &UserState<S, CurrentNonce>) -> Result<Self>;
}

/// Hash digest of sha256 hash function
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Sha256([u8; 32]);

impl Hash256 for Sha256 {
    fn hash(inp: &[u8]) -> Self {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.input(inp);

        let mut res = Sha256::default();
        res.copy_from_slice(&hasher.result());
        res
    }

    fn from_pubkey(pubkey: &PublicKey) -> Self {
        Self::hash(&pubkey.to_bytes())
    }

    fn from_user_state<S: State>(user_state: &UserState<S, CurrentNonce>) -> Result<Self> {
        let mut inp: Vec<u8> = vec![];
        user_state.write(&mut inp)?;

        Ok(Self::hash(&inp))
    }
}

impl Sha256 {
    pub fn as_array(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    fn copy_from_slice(&mut self, src: &[u8]) {
        self.0.copy_from_slice(src)
    }
}

/// User address represents last 20 bytes of digest of user's public key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserAddress([u8; 20]);

impl UserAddress {
    /// Get a user address only if the verification of signature returns true.
    pub fn from_sig(msg: &[u8], sig: &Signature, pubkey: &PublicKey) -> Self {
        assert!(pubkey.verify(msg, &sig).is_ok());
        Self::from_pubkey(&pubkey)
    }
    
    fn from_pubkey(pubkey: &PublicKey) -> Self {
        let hash = Sha256::from_pubkey(pubkey);
        let addr = &hash.as_array()[12..];
        let mut res = [0u8; 20];
        res.copy_from_slice(addr);

        UserAddress(res)
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut res = [0u8; 20];
        reader.read_exact(&mut res)?;
        Ok(UserAddress(res))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}

// TODO: Enclave's signature generation
