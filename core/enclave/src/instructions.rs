use std::{
    vec::Vec,
    marker::PhantomData,
};
use anonify_common::{UserAddress, AccessRight, Ciphertext};
use anonify_runtime::{UpdatedState, StateType, traits::*};
use codec::{Encode, Decode};
use crate::{
    error::Result,
    group_key::GroupKey,
    context::EnclaveContext,
};

#[derive(Debug, Clone, Encode, Decode)]
pub struct Instructions<S: StateTransition<G>, G: StateGetter> {
    my_addr: UserAddress,
    call_kind: S::C,
    marker: PhantomData<G>,
}

impl<S: StateTransition<G>, G: StateGetter> Instructions<S, G> {
    pub fn new(call_id: u32, params: &mut [u8], access_right: &AccessRight) -> Result<Self> {
        let my_addr = UserAddress::from_access_right(&access_right)?;
        let call_kind = S::C::from_call_id(call_id, params)?;

        Ok(Instructions {
            my_addr,
            call_kind,
            marker: PhantomData::<G>,
        })
    }

    pub fn encrypt(&self, key: &GroupKey, max_mem_size: usize) -> Result<Ciphertext> {
        // Add padding to fix the ciphertext size of all state types.
        // The padding works for fixing the ciphertext size so that
        // other people cannot distinguish what state is encrypted based on the size.
        fn append_padding(buf: &mut Vec<u8>, max_mem_size: usize) {
            let padding_size = max_mem_size - buf.len();
            let mut padding = vec![0u8; padding_size];
            buf.extend_from_slice(&mut padding);
        }

        let mut buf = self.encode();
        append_padding(&mut buf, max_mem_size);
        key.encrypt(buf).map_err(Into::into)
    }

    /// Only if the TEE belongs to the group, you can receive ciphertext and decrypt it,
    /// otherwise do nothing.
    pub fn state_transition(
        ctx: G,
        ciphertext: &Ciphertext,
        group_key: &mut GroupKey
    ) -> Result<Option<impl Iterator<Item=UpdatedState<StateType>> + Clone>> {
        if let Some(instructions) = Instructions::<S, G>::decrypt(ciphertext, group_key)? {
            let state_iter = instructions
                .stf_call(ctx)?
                .into_iter();

            return Ok(Some(state_iter))
        }

        Ok(None)
    }

    fn decrypt(ciphertext: &Ciphertext, key: &mut GroupKey) -> Result<Option<Self>> {
        match key.decrypt(ciphertext)? {
            Some(plaintext) => {
                Instructions::decode(&mut &plaintext[..])
                    .map(|p| Some(p))
                    .map_err(Into::into)
            }
            None => Ok(None)
        }
    }

    fn stf_call(self, ctx: G) -> Result<Vec<UpdatedState<StateType>>>
    {
        let res = S::new(ctx).call(
            self.call_kind,
            self.my_addr,
        )?;

        Ok(res)
    }
}
