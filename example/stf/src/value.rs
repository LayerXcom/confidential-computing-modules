use crate::serde::{Serialize, Deserialize};
use crate::State;
use crate::state_type::StateType;
use crate::localstd::{
    io::{self, Error, ErrorKind},
    vec::Vec,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct Value(u64);

impl Value {
    pub fn new(raw: u64) -> Self {
        Value(raw)
    }

    pub fn into_raw(self) -> u64 {
        self.0
    }
}

pub enum CallKind {
    Transfer,
}

// TODO: to be more generalized
pub struct Runtime(pub CallKind);

impl Runtime {
    // TODO: https://docs.rs/web3/0.10.0/src/web3/contract/tokens.rs.html#71-74
    pub fn exec<S: State>(&self, params: (S, S, S)) -> io::Result<(S, S)> {
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
pub fn transfer<S: State>(my_current: StateType, other_current: StateType, params: StateType) -> io::Result<(S, S)> {
    if my_current < params {
        return Err(Error::new(ErrorKind::InvalidData, "You don't have enough balance."));
    }
    let my_update = my_current - params;
    let other_update = other_current + params;

    Ok((my_update.into_state()?, other_update.into_state()?))
}

