use crate::State;
use crate::state_type::StateType;
use crate::localstd::{
    ops::{Add, Sub},
    boxed::Box,
    string::ToString,
};
use codec::{Encode, Decode};

pub const CIPHERTEXT_SIZE: usize = 88;

// macro_rules! state {
//     () => {

//     };
// }

// User defined state
#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd, Encode, Decode)]
pub struct Value(u64);

impl Value {
    pub fn new(raw: u64) -> Self {
        Value(raw)
    }
}

impl Add for Value {
    type Output = Value;

    fn add(self, other: Self) -> Self {
        let res = self.0 + other.0;
        Value(res)
    }
}

impl Sub for Value {
    type Output = Value;

    fn sub(self, other: Self) -> Self {
        let res = self.0 - other.0;
        Value(res)
    }
}


pub enum CallKind {
    Transfer,
}

// TODO: to be more generalized
pub struct Runtime(pub CallKind);

impl Runtime {
    // TODO: https://docs.rs/web3/0.10.0/src/web3/contract/tokens.rs.html#71-74
    pub fn exec<S: State>(&self, params: (S, S, S)) -> Result<(S, S), codec::Error> {
        match self.0 {
            CallKind::Transfer => {
                let (my_current, other_current, params) =
                    (StateType::from_state(params.0)?, StateType::from_state(params.1)?, StateType::from_state(params.2)?);
                transfer::<S>(my_current, other_current, params)
            },
        }
    }
}

// TODO: Replace Error to our own error type.
/// Devepler defined state transition function for thier applications.
pub fn transfer<S: State>(my_current: StateType, other_current: StateType, params: StateType) -> Result<(S, S), codec::Error> {
    // if my_current < params {
    //     return Err(Box("You don't have enough balance."));
    // }
    let my_update = StateType { raw: my_current.raw - params.raw };
    let other_update = StateType { raw: other_current.raw + params.raw };

    Ok((my_update.into_state()?, other_update.into_state()?))
}

