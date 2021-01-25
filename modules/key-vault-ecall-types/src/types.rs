use crate::serde::{Deserialize, Serialize};
use frame_common::{EcallInput, EcallOutput};

pub mod input {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct CallServerStarter;

    impl EcallInput for CallServerStarter {}

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct CallServerStopper;

    impl EcallInput for CallServerStopper {}
}

pub mod output {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct Empty;

    impl EcallOutput for Empty {}
}
