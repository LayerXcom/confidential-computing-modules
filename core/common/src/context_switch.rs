use crate::localstd::{
    fmt::Debug,
    collections::HashSet,
    vec::Vec,
};
use crate::local_anyhow::Result;
use crate::serde::{Serialize, Deserialize};

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
    execution: E,
    skip_phases: HashSet<u8>,
}

#[derive(Debug, Clone)]
pub struct ExecOutput(Vec<u8>);
