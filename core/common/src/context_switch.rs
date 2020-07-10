use crate::localstd::{
    fmt::Debug,
    collections::HashSet,
    vec::Vec,
};
use crate::local_anyhow::Result;
use crate::serde::{Serialize, Deserialize};
use crate::traits::State;

pub trait AccessControl: Debug + Clone {
    fn is_allowed(self) -> Result<()>;
}

pub trait Execution: Debug + Clone {
    fn exec(self) -> Option<ExecOutput>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "crate::serde")]
pub struct EcallInput<A: AccessControl, E: Execution> {
    access_control: A,
    exec_params: E,
    skip_phases: HashSet<u8>,
}

impl<A: AccessControl, E: Execution> EcallInput<A, E> {
    pub fn new(access_control: A, exec_params: E, skip_phases: HashSet<u8>) -> Self {
        EcallInput {
            access_control,
            exec_params,
            skip_phases,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecOutput(Vec<u8>);

pub struct EncryptInstructionExec<S: State> {
    state: S,
    state_id: u64,
    call_id: u32,
}


