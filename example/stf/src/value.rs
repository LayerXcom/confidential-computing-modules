use crate::State;
use crate::state_type::{StateType, U64};
use crate::localstd::{
    boxed::Box,
    string::String,
    vec::Vec,
};

pub const CIPHERTEXT_SIZE: usize = 88;

// macro_rules! state {
//     ($raw: expr) => {
//         match (&$raw) {
//             (raw_val) => {
//                 #[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd, Encode, Decode)]
//                 pub struct StateType {
//                     pub raw: raw_val,
//                 }
//             }
//         }
//     };
// }


pub enum CallKind {
    Transfer{amount: U64},
    Approve{address: String, amount: U64},
    TransferFrom{amount: U64},
    Mint{amount: U64},
    ChangeOwner{new_owner: String},
}

#[derive(Clone, Debug)]
pub enum Erc20 {
    Balance(U64),
    // allowed: (String, U64),
    TotalSupply(U64),
    Owner(String),
}

pub struct Runtime;

// TODO: state re-order attack
impl Runtime {
    pub fn call<S: State>(
        kind: CallKind,
        state: Vec<S>,
    ) -> Result<impl Iterator<Item=impl State>, codec::Error> {
        match kind {
            CallKind::Transfer{amount} => {
                assert_eq!(state.len(), 2);
                Self::transfer(
                    U64::from_state(&state[0])?,
                    U64::from_state(&state[1])?,
                    amount,
                )
            },
            _ => unimplemented!()
        }
    }

    fn transfer(
        my_current: U64,
        other_current: U64,
        amount: U64
    ) -> Result<impl Iterator<Item=impl State>, codec::Error> {
        // if my_current < amount {
        //     return Err(Box("You don't have enough balance."));
        // }
        let my_update = my_current - amount;
        let other_update = other_current + amount;

        // TODO: avoid vec because array doesn't support into_iter(), automatically translated to iter()
        // which returns &U64.
        Ok(vec![my_update, other_update].into_iter())
    }
}
