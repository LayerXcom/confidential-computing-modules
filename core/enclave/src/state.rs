//! State transition functions for anonymous asset
use anonify_types::types::*;
use crate::{
    crypto::*,
    kvs::DBValue,
    sealing::NonSealedDbValue,
    error::{Result, EnclaveError},
};
use std::{
    prelude::v1::*,
    io::{Write, Read},
    marker::PhantomData,
    convert::TryFrom,
};

/// Trait of each user's state.
pub trait State: Sized + Default {
    fn new(init: u64) -> Self;

    fn write_le<W: Write>(&self, writer: &mut W) -> Result<()>;

    fn read_le<R: Read>(reader: &mut R) -> Result<Self>;
}

/// Curret nonce for state.
/// Priventing from race condition of writing ciphertext to blockchain.
#[derive(Debug)]
pub enum CurrentNonce { }

/// Next nonce for state.
/// It'll be defined deterministically as `next_nonce = Hash(address, current_state, current_nonce)`.
#[derive(Debug)]
pub enum NextNonce { }

/// This struct can be got by decrypting ciphertexts which is stored on blockchain.
/// The secret key is shared among all TEE's enclaves.
/// State and nonce field of this struct should be encrypted before it'll store enclave's in-memory db.
#[derive(Debug, Clone)]
pub struct UserState<S: State, N> {
    address: UserAddress,
    state: S,
    nonce: Nonce,
    _marker: PhantomData<N>,
}

impl<S: State, N> UserState<S, N> {
    pub fn try_into_vec(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.write(&mut buf)?;
        Ok(buf)
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.address.write(writer)?;
        self.state.write_le(writer)?;
        self.nonce.write(writer)?;

        Ok(())
    }
}

// State with NextNonce must not be allowed to access to the database to avoid from
// storing data which have not been considered globally consensused.
impl<S: State> UserState<S, CurrentNonce> {
    pub fn decrypt(cipheriv: Vec<u8>, key: &SymmetricKey) -> Result<Self> {
        let res = decrypt_aes_256_gcm(cipheriv, key)?;
        Self::read(&res[..])
    }

    pub fn into_db_key(&self) -> Vec<u8> {
        unimplemented!();
    }

    pub fn into_db_value(&self) -> NonSealedDbValue {
        unimplemented!();
    }

    pub fn read<R: Read>(mut reader: R) -> Result<Self> {
        let address = UserAddress::read(&mut reader)?;
        let state = S::read_le(&mut reader)?;
        let nonce = Nonce::read(&mut reader)?;

        Ok(UserState {
            address,
            state,
            nonce,
            _marker: PhantomData,
        })
    }

    fn next_nonce(&self) -> Result<Nonce> {
        let next_nonce = Sha256::from_user_state(&self)?;
        Ok(next_nonce.into())
    }

    fn encrypt_db_value() {
        unimplemented!();
    }

    fn decrypt_db_value() {
        unimplemented!();
    }
}

impl<S: State> UserState<S, NextNonce> {
    pub fn new(address: UserAddress, init_state: u64) -> Result<Self> {
        let state = S::new(init_state);
        let mut buf = vec![];
        address.write(&mut buf)?;
        state.write_le(&mut buf)?;
        let nonce = Sha256::hash(&buf).into();

        Ok(UserState {
            address,
            state,
            nonce,
            _marker: PhantomData
        })
    }

    pub fn encrypt(self, key: &SymmetricKey) -> Result<Vec<u8>> {
        let buf = self.try_into_vec()?;
        encrypt_aes_256_gcm(buf, key)
    }
}

impl<S: State> TryFrom<UserState<S, CurrentNonce>> for UserState<S, NextNonce> {
    type Error = EnclaveError;

    fn try_from(s: UserState<S, CurrentNonce>) -> Result<Self> {
        let next_nonce = s.next_nonce()?;

        Ok(UserState {
            address: s.address,
            state: s.state,
            nonce: next_nonce,
            _marker: PhantomData,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Nonce([u8; 32]);

impl Nonce {
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut res = [0u8; 32];
        reader.read_exact(&mut res)?;
        Ok(Nonce(res))
    }
}

impl From<Sha256> for Nonce {
    fn from(s: Sha256) -> Self {
        Nonce(s.as_array())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write() {

    }
}
