//! State transition functions for anonymous asset

use anonify_common::{
    UserAddress, Sha256, Hash256, State,
    kvs::*,
};
use ed25519_dalek::{PublicKey, Signature};
use crate::{
    crypto::*,
    kvs::{MEMORY_DB, EnclaveKVS, EnclaveDBTx},
    error::{Result, EnclaveError},
};
use std::{
    prelude::v1::*,
    io::{Write, Read},
    marker::PhantomData,
    convert::{TryFrom, TryInto},
};

/// Curret nonce for state.
/// Priventing from race condition of writing ciphertext to blockchain.
#[derive(Debug, PartialEq)]
pub enum Current { }

/// Next nonce for state.
/// It'll be defined deterministically as `next_nonce = Hash(address, current_state, current_nonce)`.
#[derive(Debug, PartialEq)]
pub enum Next { }

/// This struct can be got by decrypting ciphertexts which is stored on blockchain.
/// The secret key is shared among all TEE's enclaves.
/// StateValue field of this struct should be encrypted before it'll store enclave's in-memory db.
/// [Example]: A size of ciphertext for each user state is 88 bytes, if inner_state is u64 value.
#[derive(Debug, Clone, PartialEq)]
pub struct UserState<S: State, N> {
    address: UserAddress,
    state_value: StateValue<S, N>,
}

/// State value per each user's state.
/// inner_state depends on the state of your application on anonify system.
/// Nonce is used to avoid data collisions when TEEs send transactions to blockchain.
#[derive(Debug, Clone, PartialEq)]
pub struct StateValue<S: State, N> {
    pub inner_state: S,
    pub nonce: Nonce,
    _marker: PhantomData<N>,
}

impl<S: State, N> StateValue<S, N> {
    pub fn new(inner_state: S, nonce: Nonce) -> Self {
        StateValue {
            inner_state,
            nonce,
            _marker: PhantomData,
        }
    }

    /// Get inner state and nonce from database value.
    pub fn from_dbvalue(db_value: DBValue) -> Result<Self> {
        let mut state = Default::default();
        let mut nonce = Default::default();

        if db_value != Default::default() {
            let reader = db_value.into_vec();
            state = S::read_le(&mut &reader[..])?;
            nonce = Nonce::read(&mut &reader[..])?;
        }

        Ok(StateValue::new(state, nonce))
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.inner_state.write_le(writer)?;
        self.nonce.write(writer)?;

        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> Result<Self> {
        let inner_state = S::read_le(&mut reader)?;
        let nonce = Nonce::read(&mut reader)?;

        Ok(StateValue::new(inner_state, nonce))
    }

    pub fn inner_state(&self) -> &S {
        &self.inner_state
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

impl<S: State, N> UserState<S, N> {
    pub fn try_into_vec(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.write(&mut buf)?;
        Ok(buf)
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.address.write(writer)?;
        self.state_value.write(writer)?;

        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> Result<Self> {
        let address = UserAddress::read(&mut reader)?;
        let state_value = StateValue::read(&mut reader)?;

        Ok(UserState {
            address,
            state_value,
        })
    }

    pub fn inner_state(&self) -> &S {
        &self.state_value.inner_state
    }

    pub fn nonce(&self) -> &Nonce {
        &self.state_value.nonce
    }
}

/// Operations of user state before sending a transaction or after fetching as a ciphertext
impl<S: State> UserState<S, Current> {
    pub fn new(address: UserAddress, state_value: StateValue<S, Current>) -> Self {
        UserState {
            address,
            state_value,
        }
    }
    // /// Apply user defined state transition function to current state.
    // pub fn apply_stf<F>(&self, stf: F) -> Result<Vec<UserState<S, Next>>>
    // where
    //     F: FnOnce(S, S, S) -> (S, S)
    // {
    //     let my_current_balance = self.state_value::from_dbvalue()

    //     let (my_update_state, other_update_state) = stf();
    //     let my_update: UserState<S, Next> = self.update_inner_state(my_update_state).try_into()?;
    //     let other_update: UserState<S, Next>
    // }

    // Only State with `Current` allows to access to the database to avoid from
    // storing data which have not been considered globally consensused.
    pub fn insert_cipheriv_memdb(cipheriv: Vec<u8>) -> Result<()> {
        let user_state = Self::decrypt(cipheriv, &SYMMETRIC_KEY)?;
        let key = user_state.get_db_key();
        let value = user_state.get_db_value()?;

        let mut dbtx = EnclaveDBTx::new();
        dbtx.put(&key, &value);
        MEMORY_DB.write(dbtx);

        Ok(())
    }

    /// Decrypt Ciphertext which was stored in a shared ledger.
    pub fn decrypt(cipheriv: Vec<u8>, key: &SymmetricKey) -> Result<Self> {
        let res = decrypt_aes_256_gcm(cipheriv, key)?;
        Self::read(&res[..])
    }

    /// Get in-memory database key.
    pub fn get_db_key(&self) -> &UserAddress {
        &self.address
    }

    /// Get in-memory database value.
    // TODO: Encrypt with sealing key.
    pub fn get_db_value(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.state_value.write(&mut buf)?;

        Ok(buf)
    }

    pub fn update_inner_state(&self, update: S) -> Self {
        UserState {
            address: self.address,
            state_value: StateValue::new(update, *self.nonce()),
        }
    }

    pub fn from_address_and_db_value(
        address: UserAddress,
        db_value: DBValue
    ) -> Result<Self> {
        let state_value = StateValue::from_dbvalue(db_value)?;

        Ok(UserState {
            address,
            state_value,
        })
    }

    /// Compute hash digest of current user state.
    pub fn hash(&self) -> Result<Sha256> {
        let mut inp: Vec<u8> = vec![];
        self.write(&mut inp)?;

        Ok(Sha256::hash(&inp))
    }

    fn next_nonce(&self) -> Result<Nonce> {
        let next_nonce = self.hash()?;
        Ok(next_nonce.into())
    }

    fn encrypt_db_value() {
        unimplemented!();
    }

    fn decrypt_db_value() {
        unimplemented!();
    }
}

impl<S: State> UserState<S, Next> {
    /// Initialize userstate. nonce is defined with `Sha256(address || init_state)`.
    pub fn init(address: UserAddress, init_state: S) -> Result<Self> {
        let mut buf = vec![];
        address.write(&mut buf)?;
        init_state.write_le(&mut buf)?;
        let nonce = Sha256::hash(&buf).into();
        let state_value = StateValue::new(init_state, nonce);

        Ok(UserState {
            address,
            state_value,
        })
    }

    pub fn encrypt(self, key: &SymmetricKey) -> Result<Vec<u8>> {
        let buf = self.try_into_vec()?;
        encrypt_aes_256_gcm(buf, key)
    }
}

impl<S: State> TryFrom<UserState<S, Current>> for UserState<S, Next> {
    type Error = EnclaveError;

    fn try_from(s: UserState<S, Current>) -> Result<Self> {
        let next_nonce = s.next_nonce()?;
        let inner_state = s.state_value.inner_state;
        let state_value = StateValue::new(inner_state, next_nonce);

        Ok(UserState {
            address: s.address,
            state_value,
        })
    }
}

/// To avoid data collision when a transaction is sent to a blockchain.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Nonce([u8; 32]);

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct StfWrapper<D: EnclaveKVS>{
    my_addr: UserAddress,
    target_addr: UserAddress,
    db: D,
}

impl<D: EnclaveKVS> StfWrapper<D> {
    pub fn new(
        pubkey: PublicKey,
        sig: Signature,
        msg: &[u8],
        target_addr: UserAddress,
        db: D,
    ) -> Self {
        let my_addr = UserAddress::from_sig(&msg, &sig, &pubkey);

        StfWrapper {
            my_addr,
            target_addr,
            db,
        }
    }

    // TODO: To be more generic parameters to stf.
    // TODO: Fix dupulicate state values.
    pub fn apply<F, S, I>(self, stf: F, input: S, symm_key: &SymmetricKey) -> Result<(Vec<u8>, usize)>
    where
        F: FnOnce(S, S, S) -> Result<(S, S)>, // TODO: Implement StateInput trait to tuple.
        S: State,
        I: IntoIterator<Item=S>,
    {
        let my_state_value = self.db.get(&self.my_addr);
        let my_state_value = StateValue::<S, Current>::from_dbvalue(my_state_value)?;
        let other_state_value = self.db.get(&self.target_addr);
        let other_state_value = StateValue::<S, Current>::from_dbvalue(other_state_value)?;

        let (my_update, other_update) = stf(my_state_value.inner_state.clone(), other_state_value.inner_state.clone(), input)?;
        let my_update_state: UserState::<S, Next> = UserState::<S, Current>::new(self.my_addr, my_state_value)
            .update_inner_state(my_update)
            .try_into()?;
        let mut my_enc_state = my_update_state.encrypt(&symm_key)?;
        let other_update_state: UserState::<S, Next> = UserState::<S, Current>::new(self.target_addr, other_state_value)
            .update_inner_state(other_update)
            .try_into()?;
        let mut other_enc_state = other_update_state.encrypt(&symm_key)?;

        my_enc_state.append(&mut other_enc_state);
        Ok((my_enc_state, 2))
    }
}


#[cfg(debug_assertions)]
pub mod tests {
    use super::*;
    use anonify_common::stf::Value;
    use ed25519_dalek::{SecretKey, PublicKey, Keypair, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

    const SECRET_KEY_BYTES: [u8; SECRET_KEY_LENGTH] = [
        062, 070, 027, 163, 092, 182, 011, 003,
        077, 234, 098, 004, 011, 127, 079, 228,
        243, 187, 150, 073, 201, 137, 076, 022,
        085, 251, 152, 002, 241, 042, 072, 054, ];

    const PUBLIC_KEY_BYTES: [u8; PUBLIC_KEY_LENGTH] = [
        130, 039, 155, 015, 062, 076, 188, 063,
        124, 122, 026, 251, 233, 253, 225, 220,
        014, 041, 166, 120, 108, 035, 254, 077,
        160, 083, 172, 058, 219, 042, 086, 120, ];

    pub fn test_read_write() {
        let secret = SecretKey::from_bytes(&SECRET_KEY_BYTES).unwrap();
        let public = PublicKey::from_bytes(&PUBLIC_KEY_BYTES).unwrap();
        let keypair = Keypair { secret, public };

        let mut buf = vec![];
        Value::new(100).write_le(&mut buf).expect("Faild to write value.");

        let sig = keypair.sign(&buf);
        let user_address = UserAddress::from_sig(&buf, &sig, &public);

        let state = UserState::<Value, Next>::init(user_address, Value::new(100)).unwrap();
        let state_vec = state.try_into_vec().unwrap();
        let res = UserState::read(&state_vec[..]).unwrap();

        assert_eq!(state, res);
    }
}
