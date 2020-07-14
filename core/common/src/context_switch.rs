use crate::localstd::{
    fmt::Debug,
    collections::BTreeSet,
    vec::Vec,
};
use crate::local_anyhow::Result;
use crate::traits::State;
use codec::{Encode, Decode};

pub const ENCRYPT_INSTRUCTION_CMD: u32 = 1;

pub trait AccessControl: Debug + Clone {
    fn is_allowed(self) -> Result<()>;
}

pub trait Execution: Debug + Clone {
    fn exec(self) -> Option<ExecOutput>;
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct EcallInputType<A: AccessControl, E: Execution> {
    access_control: A,
    exec_params: E,
    skip_phases: BTreeSet<u8>,
}

impl<A: AccessControl, E: Execution> EcallInputType<A, E> {
    pub fn new(access_control: A, exec_params: E, skip_phases: BTreeSet<u8>) -> Self {
        EcallInputType {
            access_control,
            exec_params,
            skip_phases,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecOutput(Vec<u8>);
