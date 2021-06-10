use crate::serde::{Deserialize, Serialize};
use frame_common::{EnclaveInput, EnclaveOutput};

pub mod input {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct CallServerStarter;

    impl EnclaveInput for CallServerStarter {}

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct CallServerStopper;

    impl EnclaveInput for CallServerStopper {}
}

pub mod output {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone, Default)]
    #[serde(crate = "crate::serde")]
    pub struct Empty;

    impl EnclaveOutput for Empty {}
}
