use frame_host::ecall_controller::*;
use key_vault_ecall_types::*;

pub const EI_MAX_SIZE: usize = 2048;

pub struct StartServerWorkflow;

impl EcallController for StartServerWorkflow {
    type HI = host_input::StartServer;
    type EI = input::CallServerStarter;
    type EO = output::Empty;
    type HO = host_output::StartServer;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub struct StopServerWorkflow;

impl EcallController for StopServerWorkflow {
    type HI = host_input::StopServer;
    type EI = input::CallServerStopper;
    type EO = output::Empty;
    type HO = host_output::StopServer;
    const EI_MAX_SIZE: usize = EI_MAX_SIZE;
}

pub mod host_input {
    use super::*;

    pub struct StartServer {
        ecall_cmd: u32,
    }

    impl StartServer {
        pub fn new(ecall_cmd: u32) -> Self {
            StartServer { ecall_cmd }
        }
    }

    impl HostInput for StartServer {
        type EnclaveInput = input::CallServerStarter;
        type HostOutput = host_output::StartServer;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            Ok((Self::EnclaveInput::default(), Self::HostOutput::default()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }

    pub struct StopServer {
        ecall_cmd: u32,
    }

    impl StopServer {
        pub fn new(ecall_cmd: u32) -> Self {
            StopServer { ecall_cmd }
        }
    }

    impl HostInput for StopServer {
        type EnclaveInput = input::CallServerStopper;
        type HostOutput = host_output::StopServer;

        fn apply(self) -> anyhow::Result<(Self::EnclaveInput, Self::HostOutput)> {
            Ok((Self::EnclaveInput::default(), Self::HostOutput::default()))
        }

        fn ecall_cmd(&self) -> u32 {
            self.ecall_cmd
        }
    }
}

pub mod host_output {
    use super::*;

    #[derive(Default)]
    pub struct StartServer;

    impl HostOutput for StartServer {
        type EnclaveOutput = output::Empty;
    }

    #[derive(Default)]
    pub struct StopServer;

    impl HostOutput for StopServer {
        type EnclaveOutput = output::Empty;
    }
}
