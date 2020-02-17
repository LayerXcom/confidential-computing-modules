use crate::State;
use crate::state_type::*;
use crate::localstd::{
    boxed::Box,
    string::String,
    vec::Vec,
};

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



pub fn call_name_to_id(name: &str) -> u32 {
    match name {
        "Transfer" => 0,
        "Approve" => 1,
        "TransferFrom" => 2,
        "Mint" => 3,
        "ChangeOwner" => 4,
        _ => panic!("invalid call name"),
    }
}

pub enum CallKind {
    // Transfer{amount: U64, target: Address},
    Transfer{amount: U64},
    Approve{allowed: Mapping},
    TransferFrom{amount: U64},
    Mint{amount: U64},
    ChangeOwner{new_owner: Address},
}

impl CallKind {
    pub fn from_call_id(id: u32, state: &mut [u8]) -> Result<Self, codec::Error> {
        match id {
            0 => Ok(CallKind::Transfer{amount: U64::from_bytes(state)?}),
            _ => return Err("Invalid Call ID".into()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Storage {
    Balance(U64),
    // allowed: (Address, U64),
    TotalSupply(U64), // global
    Owner(Address), // global
}

pub struct Runtime;

// TODO: state re-order attack
impl Runtime {
    pub fn call<S: State>(
        kind: CallKind,
        state: Vec<S>,
        my_addr: [u8; 20],
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
        // sender: Address,
        // amount: U64,
        my_current: U64,
        other_current: U64,
        amount: U64
    ) -> Result<impl Iterator<Item=impl State>, codec::Error> {
        if my_current < amount {
            return Err("You don't have enough balance.".into());
        }
        let my_update = my_current - amount;
        let other_update = other_current + amount;

        // TODO: avoid vec because array doesn't support into_iter(), automatically translated to iter()
        // which returns &U64.
        Ok(vec![my_update, other_update].into_iter())
    }
}
