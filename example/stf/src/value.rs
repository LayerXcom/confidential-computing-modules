use crate::State;
use crate::state_type::*;
use crate::localstd::{
    boxed::Box,
    string::String,
    vec::Vec,
};
use anonify_common::UserAddress;
use codec::{Encode, Decode};

macro_rules! impl_mem {
    ( $($id:expr, $name:expr, Address => $value:ty);* ;) => {
        pub fn mem_name_to_id(name: &str) -> MemId {
            match name {
                $( $name => MemId::from_raw($id) ),* ,
                _ => panic!("invalid mem name"),
            }
        }
    };
}

impl_mem!{
    0, "Balance", Address => U64;
    1, "Balance2", Address => U64;
}

/// State identifier stored in memory.
#[derive(Encode, Decode, Debug, Clone, Copy, PartialOrd, PartialEq, Default, Eq, Ord, Hash)]
pub struct MemId(u32);

impl MemId {
    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn from_raw(u: u32) -> Self {
        MemId(u)
    }
}

/// A getter of state stored in enclave memory.
pub trait StateGetter {
    /// Get dstate using memory name.
    /// Assumed this is called in user-defined state transition functions.
    fn get<S: State>(&self, key: &UserAddress, name: &str) -> Result<S, codec::Error>;

    /// Get state using memory id.
    /// Assumed this is called by state getting operations from outside enclave.
    fn get_by_id(&self, key: &UserAddress, mem_id: MemId) -> StateType;
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
    ChangeOwner{new_owner: UserAddress},
}

impl CallKind {
    pub fn from_call_id(id: u32, state: &mut [u8]) -> Result<Self, codec::Error> {
        match id {
            0 => Ok(CallKind::Constructor(Constructor::from_bytes(state)?)),
            1 => Ok(CallKind::Transfer(Transfer::from_bytes(state)?)),
            _ => return Err("Invalid Call ID".into()),
        }
    }

    pub fn max_size(&self) -> usize {
        unimplemented!();
    }
}

#[macro_export]
macro_rules! impl_runtime {
    (
        $( $t:tt )*
    ) => {
        impl_inner_runtime!(@imp
            $($t)*
        );
    };
}

macro_rules! impl_inner_runtime {
    (@imp
        $(
            pub fn $fn_name:ident(
                $runtime:ident
                $(, $param_name:ident : $param:ty )*
            ) -> Result<Vec<UpdatedState<StateType>>,codec::Error> {
                $( $impl:tt )*
            }
        )*
    ) => {
        pub struct Runtime<G: StateGetter> {
            db: G,
        }

        impl<G: StateGetter> Runtime<G> {
            pub fn new(db: G) -> Self {
                Runtime {
                    db,
                }
            }

            pub fn call(
                self,
                kind: CallKind,
                my_addr: UserAddress,
            ) -> Result<Vec<UpdatedState<StateType>>, codec::Error> {
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

            $(
                pub fn $fn_name (
                    $runtime
                    // sender: UserAddress
                    $(, $param_name : $param )*
                ) -> Result<Vec<UpdatedState<StateType>>,codec::Error> {
                    $( $impl )*
                }
            )*
        }
    };
}

impl_runtime!{
    pub fn constructor(
        self,
        sender: UserAddress,
        total_supply: U64
    ) -> Result<Vec<UpdatedState<StateType>>,codec::Error> {
        let init = UpdatedState::new(sender, "Balance", total_supply.into());

        Ok(vec![init])
    }

    pub fn transfer(
        self,
        sender: UserAddress,
        target: UserAddress,
        amount: U64
    ) -> Result<Vec<UpdatedState<StateType>>,codec::Error> {
        let my_balance = self.db.get::<U64>(&sender, "Balance")?;
        let target_balance = self.db.get::<U64>(&target, "Balance")?;

        if my_balance < amount {
            return Err("You don't have enough balance.".into());
        }
        let my_update = my_balance - amount;
        let other_update = target_balance + amount;

        let my = UpdatedState::new(sender, "Balance", my_update.into());
        let other = UpdatedState::new(target, "Balance", other_update.into());

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
