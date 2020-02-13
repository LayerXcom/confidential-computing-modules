//! State transition functions for anonymous asset

use anonify_common::{
    UserAddress, Sha256, Hash256, State, Ciphertext, LockParam, AccessRight,
    kvs::*,
    Runtime, CallKind,
};
use codec::{Input, Output};
use crate::{
    crypto::*,
    kvs::{EnclaveDB, EnclaveDBTx},
    error::{Result, EnclaveError},
    context::EnclaveContext,
};
use std::{
    prelude::v1::*,
    io::{Write, Read},
    marker::PhantomData,
    convert::{TryFrom, TryInto},
};

/// Service for state transition operations
pub struct StateService<S: State>{
    my_state: UserState<S, Current>,
    other_state: UserState<S, Current>,
}

impl<S> StateService<S>
where
    S: State,
{
    pub fn from_access_right<DB: EnclaveDB>(
        access_right: &AccessRight,
        target_addr: UserAddress,
        ctx: &EnclaveContext<DB>,
    ) -> Result<Self> {
        let my_addr = UserAddress::from_access_right(access_right)?;

        let my_dv = ctx.get(&my_addr);
        let my_state = UserState::<S, Current>::from_db_value(my_addr, my_dv)?;
        let other_dv = ctx.get(&target_addr);
        let other_state = UserState::<S, Current>::from_db_value(target_addr, other_dv)?;

        Ok(StateService {
            my_state,
            other_state,
        })
    }

    pub fn reveal_lock_params(&self) -> Vec<LockParam> {
        let mut res = vec![];
        res.push(*self.my_state.lock_param());
        res.push(*self.other_state.lock_param());
        res
    }

    // TODO: To be more generic parameters to stf.
    // TODO: Fix dupulicate state values.
    pub fn apply(
        self,
        _stf: &str,
        params: S,
        symm_key: &SymmetricKey
    ) -> Result<Vec<Ciphertext>> {
        let (my_update, other_update) = Runtime(CallKind::Transfer)
            .exec((self.my_state.inner_state().clone(), self.other_state.inner_state().clone(), params))?;

        let my_update_state: UserState::<S, Next> = self.my_state
            .update_inner_state(my_update)
            .try_into()?;
        let other_update_state: UserState::<S, Next> = self.other_state
            .update_inner_state(other_update)
            .try_into()?;

        let my_enc_state = my_update_state.encrypt(&symm_key)?;
        let other_enc_state = other_update_state.encrypt(&symm_key)?;
        let mut res = vec![];
        res.push(my_enc_state);
        res.push(other_enc_state);

        Ok(res)
    }
}

/// Curret generation of lock parameter for state.
/// Priventing from race condition of writing ciphertext to blockchain.
#[derive(Debug, Clone, PartialEq)]
pub enum Current { }

/// Next generation of lock parameter for state.
/// It'll be defined deterministically as `next_lock_param = Hash(address, current_state, current_lock_param)`.
#[derive(Debug, Clone, PartialEq)]
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

impl<S: State, N> UserState<S, N> {
    pub fn try_into_vec(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.write(&mut buf)?;
        Ok(buf)
    }

    pub fn write<W: Write + Output>(&self, writer: &mut W) -> Result<()> {
        self.address.write(writer)?;
        self.state_value.write(writer)?;

        Ok(())
    }

    pub fn read<R: Read + Input>(mut reader: R) -> Result<Self> {
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

    pub fn lock_param(&self) -> &LockParam {
        &self.state_value.lock_param
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

    pub fn from_db_value(
        address: UserAddress,
        db_value: DBValue
    ) -> Result<Self> {
        let state_value = StateValue::from_dbvalue(db_value)?;

        Ok(UserState {
            address,
            state_value,
        })
    }

    // Only State with `Current` allows to access to the database to avoid from
    // storing data which have not been considered globally consensused.
    pub fn insert_cipheriv_memdb<DB: EnclaveDB>(
        cipheriv: Ciphertext,
        symm_key: &SymmetricKey,
        ctx: &EnclaveContext<DB>,
    ) -> Result<()> {
        let user_state = Self::decrypt(cipheriv, &symm_key)?;
        let key = user_state.get_db_key();
        let value = user_state.get_db_value()?;

        let mut dbtx = EnclaveDBTx::new();
        dbtx.put(&key, &value);
        ctx.write(dbtx);

        Ok(())
    }

    /// Decrypt Ciphertext which was stored in a shared ledger.
    pub fn decrypt(cipheriv: Ciphertext, key: &SymmetricKey) -> Result<Self> {
        let res = key.decrypt_aes_256_gcm(cipheriv)?;
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
            state_value: StateValue::new(update, *self.lock_param()),
        }
    }

    /// Compute hash digest of current user state.
    fn hash(&self) -> Result<Sha256> {
        let mut inp: Vec<u8> = vec![];
        self.write(&mut inp)?;

        Ok(Sha256::hash(&inp))
    }

    fn next_lock_param(&self) -> Result<LockParam> {
        let next_lock_param = self.hash()?;
        Ok(next_lock_param.into())
    }

    fn encrypt_db_value() {
        unimplemented!();
    }

    fn decrypt_db_value() {
        unimplemented!();
    }
}

impl<S: State> UserState<S, Next> {
    /// Initialize userstate. lock_param is defined with `Sha256(address || init_state)`.
    pub fn init(address: UserAddress, init_state: S) -> Result<Self> {
        let mut buf = vec![];
        address.write(&mut buf)?;
        init_state.write_le(&mut buf);
        let lock_param = Sha256::hash(&buf).into();
        let state_value = StateValue::new(init_state, lock_param);

        Ok(UserState {
            address,
            state_value,
        })
    }

    pub fn encrypt(self, key: &SymmetricKey) -> Result<Ciphertext> {
        let buf = self.try_into_vec()?;
        key.encrypt_aes_256_gcm(buf)
    }
}

impl<S: State> TryFrom<UserState<S, Current>> for UserState<S, Next> {
    type Error = EnclaveError;

    fn try_from(s: UserState<S, Current>) -> Result<Self> {
        let next_lock_param = s.next_lock_param()?;
        let inner_state = s.state_value.inner_state;
        let state_value = StateValue::new(inner_state, next_lock_param);

        Ok(UserState {
            address: s.address,
            state_value,
        })
    }
}

/// State value per each user's state.
/// inner_state depends on the state of your application on anonify system.
/// LockParam is used to avoid data collisions when TEEs send transactions to blockchain.
#[derive(Debug, Clone, PartialEq)]
pub struct StateValue<S: State, N> {
    pub inner_state: S,
    pub lock_param: LockParam,
    _marker: PhantomData<N>,
}

impl<S: State, N> StateValue<S, N> {
    pub fn new(inner_state: S, lock_param: LockParam) -> Self {
        StateValue {
            inner_state,
            lock_param,
            _marker: PhantomData,
        }
    }

    /// Get inner state and lock_param from database value.
    pub fn from_dbvalue(db_value: DBValue) -> Result<Self> {
        let mut state = Default::default();
        let mut lock_param = Default::default();

        if db_value != Default::default() {
            let reader = db_value.into_vec();
            state = S::read_le(&mut &reader[..])?;
            lock_param = LockParam::read(&mut &reader[..])?;
        }

        Ok(StateValue::new(state, lock_param))
    }

    pub fn write<W: Write + Output>(&self, writer: &mut W) -> Result<()> {
        self.inner_state.write_le(writer);
        self.lock_param.write(writer)?;

        Ok(())
    }

    pub fn read<R: Read + Input>(reader: &mut R) -> Result<Self> {
        let inner_state = S::read_le(reader)?;
        let lock_param = LockParam::read(reader)?;

        Ok(StateValue::new(inner_state, lock_param))
    }

    pub fn inner_state(&self) -> &S {
        &self.inner_state
    }

    pub fn lock_param(&self) -> &LockParam {
        &self.lock_param
    }
}

#[cfg(debug_assertions)]
pub mod tests {
    use super::*;
    use anonify_common::StateType;
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
        StateType::new(100).write_le(&mut buf);

        let sig = keypair.sign(&buf);
        let user_address = UserAddress::from_sig(&buf, &sig, &public).unwrap();

        let state = UserState::<StateType, Next>::init(user_address, StateType::new(100)).unwrap();
        let state_vec = state.try_into_vec().unwrap();
        let res = UserState::read(&state_vec[..]).unwrap();

        assert_eq!(state, res);
    }
}
