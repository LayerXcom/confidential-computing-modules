use crate::localstd::{
    io::{self, Read, Write},
};
use ed25519_dalek::{PublicKey, Signature};
use tiny_keccak::Keccak;
use serde::{Deserialize, Serialize};

/// Trait for 256-bits hash functions
pub trait Hash256 {
    fn hash(inp: &[u8]) -> Self;

    fn from_pubkey(pubkey: &PublicKey) -> Self;
}

/// User address represents last 20 bytes of digest of user's public key.
/// A signature verification must return true to generate a user address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut res = [0u8; 20];
        reader.read_exact(&mut res)?;
        Ok(UserAddress(res))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn from_array(array: [u8; 20]) -> Self {
        UserAddress(array)
    }
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

/// A trait that will hash using Keccak256 the object it's implemented on.
pub trait Keccak256<T> {
    /// This will return a sized object with the hash
    fn keccak256(&self) -> T where T: Sized;
}

impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(result.as_mut());
        result
    }
}
