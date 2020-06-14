use std::vec::Vec;
use anonify_app_preluder::{CIPHERTEXT_SIZE, Ciphertext, CallKind, MAX_MEM_SIZE, Runtime};
use anonify_common::{UserAddress, AccessRight};
use anonify_runtime::{UpdatedState, State, StateType};
use codec::{Encode, Decode};
use crate::{
    error::Result,
    group_key::GroupKey,
    context::EnclaveContext,
};

#[derive(Debug, Clone, Encode, Decode)]
pub struct Instructions {
    my_addr: UserAddress,
    call_kind: CallKind,
}

impl Instructions {
    pub fn new(call_id: u32, params: &mut [u8], access_right: &AccessRight) -> Result<Self> {
        let my_addr = UserAddress::from_access_right(&access_right)?;
        let call_kind = CallKind::from_call_id(call_id, params)?;

        Ok(Instructions {
            my_addr,
            call_kind,
        })
    }

    pub fn encrypt(&self, key: &GroupKey) -> Result<Ciphertext> {
        // Add padding to fix the ciphertext size of all state types.
        // The padding works for fixing the ciphertext size so that
        // other people cannot distinguish what state is encrypted based on the size.
        fn append_padding(buf: &mut Vec<u8>) {
            let padding_size = MAX_MEM_SIZE - buf.len();
            let mut padding = vec![0u8; padding_size];
            buf.extend_from_slice(&mut padding);
        }

        let mut buf = self.encode();
        append_padding(&mut buf);
        key.encrypt(buf).map_err(Into::into)
    }

    pub fn decrypt(ciphertext: &Ciphertext, key: &mut GroupKey) -> Result<Option<Self>> {
        match key.decrypt(ciphertext)? {
            Some(plaintext) => {
                Instructions::decode(&mut &plaintext[..])
                    .map(|p| Some(p))
                    .map_err(Into::into)
            }
            None => Ok(None)
        }
    }

    pub fn state_transition<S: State>(self, ctx: &EnclaveContext<StateType>) -> Result<Vec<UpdatedState<StateType>>> {
        let res = Runtime::new(ctx.clone()).call(
            self.call_kind,
            self.my_addr,
        )?;

        Ok(res)
    }
}
