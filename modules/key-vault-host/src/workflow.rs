use anonify_io_types::*;
use config::constants::*;
use frame_host::engine::*;
use frame_mra_tls::primitives::{Certificate, PrivateKey};

pub const OUTPUT_MAX_LEN: usize = 2048;

pub struct StartServerWorkflow;

impl HostEngine for StartServerWorkflow {
    type HI = host_input::StartServer;
    type EI = input::CallStartServer;
    type EO = output::Empty;
    type HO = host_output::StartServer;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = START_SERVER_CMD;
}

pub struct StopServerWorkflow;

impl HostEngine for StopServerWorkflow {
    type HI = host_input::StopServer;
    type EI = input::CallStopServer;
    type EO = output::Empty;
    type HO = host_output::StopServer;
    const OUTPUT_MAX_LEN: usize = OUTPUT_MAX_LEN;
    const CMD: u32 = STOP_SERVER_CMD;
}

pub mod host_input {
    use super::*;

    pub struct StartServer {
        private_key: PrivateKey,
        certificates: Vec<Certificate>,
    }

    impl StartServer {
        pub fn new(private_key: PrivateKey, certificates: Vec<Certificate>) -> Self {
            StartServer {
                private_key,
                certificates,
            }
        }
    }

    impl HostInput for StartServer {
        type EcallInput = input::CallServerStarter;
        type HostOutput = host_output::StartServer;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            let ecall_input = Self::EcallInput::new(self.private_key, self.certificates);

            Ok((ecall_input, Self::HostOutput::default()))
        }
    }

    #[derive(Default)]
    pub struct StopServer;

    impl HostInput for StopServer {
        type EcallInput = input::CallServerStopper;
        type HostOutput = host_output::StopServer;

        fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
            Ok((Self::EcallInput::default(), Self::HostOutput::default()))
        }
    }
}

pub mod host_output {
    use super::*;

    #[derive(Default)]
    pub struct StartServer;

    impl HostOutput for StartServer {
        type EcallOutput = output::Empty;
    }

    #[derive(Default)]
    pub struct StopServer;

    impl HostOutput for StopServer {
        type EcallOutput = output::Empty;
    }
}
