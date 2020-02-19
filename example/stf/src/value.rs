use crate::State;
use crate::state_type::*;
use crate::localstd::{
    boxed::Box,
    string::String,
    vec::Vec,
};
use anonify_common::{UserAddress, MemId};
use codec::{Encode, Decode};

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

/// A getter of state stored in enclave memory.
pub trait StateGetter {
    fn get<S: State>(&self, key: &UserAddress, name: &str) -> Result<S, codec::Error>;
}

pub fn mem_name_to_id(name: &str) -> MemId {
    match name {
        "Balance" => MemId(0),
        _ => panic!("invalid mem name"),
    }
}

pub fn call_name_to_id(name: &str) -> u32 {
    match name {
        "Constructor" => 0,
        "Transfer" => 1,
        "Approve" => 2,
        "TransferFrom" => 3,
        "Mint" => 4,
        "ChangeOwner" => 5,
        _ => panic!("invalid call name"),
    }
}

#[derive(Encode, Decode, Debug, Clone, Default)]
pub struct Constructor {
    pub init: U64,
}

#[derive(Encode, Decode, Debug, Clone, Default)]
pub struct Transfer {
    pub amount: U64,
    pub target: UserAddress,
}

pub enum CallKind {
    Constructor(Constructor),
    Transfer(Transfer),
    Approve{allowed: Mapping},
    TransferFrom{amount: U64},
    Mint{amount: U64},
    ChangeOwner{new_owner: Address},
}

impl CallKind {
    pub fn from_call_id(id: u32, state: &mut [u8]) -> Result<Self, codec::Error> {
        match id {
            0 => Ok(CallKind::Transfer(Transfer::from_bytes(state)?)),
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

pub struct Runtime<G: StateGetter> {
    db: G,
}

// TODO: state re-order attack
impl<G: StateGetter> Runtime<G> {
    pub fn new(db: G) -> Self {
        Runtime {
            db,
        }
    }

    pub fn call(
        &self,
        kind: CallKind,
        my_addr: UserAddress,
    ) -> Result<Vec<UpdatedState<impl State>>, codec::Error> {
        match kind {
            CallKind::Constructor(constructor) => {
                self.constructor(
                    my_addr,
                    constructor.init,
                )
            },
            CallKind::Transfer(transfer) => {
                self.transfer(
                    my_addr,
                    transfer.target,
                    transfer.amount,
                )
            },
            _ => unimplemented!()
        }
    }

    fn constructor(
        &self,
        sender: UserAddress,
        total_supply: U64,
    ) -> Result<Vec<UpdatedState<U64>>, codec::Error> {
        let init = UpdatedState::new(sender, "Balance", total_supply);

        Ok(vec![init])
    }

    fn transfer(
        &self,
        sender: UserAddress,
        target: UserAddress,
        amount: U64,
    ) -> Result<Vec<UpdatedState<U64>>, codec::Error> {
        let my_balance = self.db.get::<U64>(&sender, "Balance")?;
        let target_balance = self.db.get::<U64>(&target, "Balance")?;

        if my_balance < amount {
            return Err("You don't have enough balance.".into());
        }
        let my_update = my_balance - amount;
        let other_update = target_balance + amount;

        let my = UpdatedState::new(sender, "Balance", my_update);
        let other = UpdatedState::new(target, "Balance", other_update);

        Ok(vec![my, other])
    }
}

#[derive(Debug, Clone)]
pub struct UpdatedState<S: State> {
    pub address: UserAddress,
    pub mem_id: MemId,
    pub state: S,
}

impl<S: State> UpdatedState<S> {
    pub fn new(address: UserAddress, mem_name: &str, state: S) -> Self {
        let mem_id = mem_name_to_id(mem_name);
        UpdatedState {
            address,
            mem_id,
            state
        }
    }
}

pub fn into_trait<S: State>(s: UpdatedState<impl State>) -> Result<UpdatedState<S>, codec::Error> {
    let state = S::from_state(&s.state)?;
    Ok(UpdatedState {
        address: s.address,
        mem_id: s.mem_id,
        state,
    })
}
