use codec::{Decode, Encode};
use frame_common::{EcallInput, EcallOutput};

pub mod input {
    use super::*;

    #[derive(Encode, Decode, Debug, Clone, Default)]
    pub struct CallServerStarter;

    impl EcallInput for CallServerStarter {}

    #[derive(Encode, Decode, Debug, Clone, Default)]
    pub struct CallServerStopper;

    impl EcallInput for CallServerStopper {}
}

pub mod output {
    use super::*;

    #[derive(Encode, Decode, Debug, Clone, Default)]
    pub struct Empty;

    impl EcallOutput for Empty {}
}
