//! State transition functions for anonymous asset
use anonify_types::types::*;
use crate::{
    crypto::*,
    kvs::DBValue,
    sealing::NonSealedDbValue,
    error::Result,
};
use std::{
    prelude::v1::*,
    io::{Write, Read},
    marker::PhantomData,
};

pub trait State: Sized {
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

// State with NextNonce must not be allowed to access to the database to avoid from
// storing data which have not been considered globally consensused.
impl<S: State> UserState<S, CurrentNonce> {
    pub fn decrypt(ciphertext: Ciphertext, key: &SymmetricKey) -> Self {
        unimplemented!();
    }

    fn sha256(&self) -> Sha256 {


        unimplemented!();
    }

    pub fn into_db_key(&self) -> Vec<u8> {
        unimplemented!();
    }

    pub fn into_db_value(&self) -> NonSealedDbValue {
        unimplemented!();
    }

    pub fn from_bytes() -> Self {
        unimplemented!();
    }

    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.address.write(writer)?;
        self.state.write_le(writer)?;
        self.nonce.write(writer)?;

        Ok(())
    }

    fn next_nonce(&self) -> Nonce {
        unimplemented!();
    }

    fn encrypt_db_value() {
        unimplemented!();
    }

    fn decrypt_db_value() {
        unimplemented!();
    }
}

impl<S: State> UserState<S, NextNonce> {
    pub fn encrypt(&self, key: &SymmetricKey) -> Result<Ciphertext> {
        // encrypt_aes_256_gcm(, key)
        unimplemented!();
    }
}

impl<S: State> From<UserState<S, CurrentNonce>> for UserState<S, NextNonce> {
    fn from(s: UserState<S, CurrentNonce>) -> Self {
        //TODO: Cul next nonce.
        let next_nonce = s.next_nonce();
        unimplemented!();
        // UserState {
        //     address: s.address,
        //     state: s.state,
        //     nonce: nonce,
        //     _marker: PhantomData,
        // }
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
