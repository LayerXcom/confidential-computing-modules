use crate::handlers::BackupHandler;
use anonify_io_types::*;
use frame_common::state_types::StateType;
use frame_mra_tls::{Server, ServerConfig};
use frame_runtime::traits::*;
use frame_enclave::EnclaveEngine;
use std::thread;

const SERVER_ADDRESS: &str = "0.0.0.0:12345";

/// A server starter
#[derive(Debug, Clone)]
pub struct ServerStarter;

impl EnclaveEngine for ServerStarter {
    type EI = input::CallServerStarter;
    type EO = output::Empty;

    fn handle<R, C>(
        ecall_input: Self::EI,
        _enclave_context: &C,
        _max_mem_size: usize,
    ) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let certificates = ecall_input.certificates();
        let private_key = ecall_input.private_key();
        let mut server_config = ServerConfig::default();
        server_config.set_single_cert(certificates, private_key)?;

        let mut server = Server::new(SERVER_ADDRESS, server_config);
        let handler = BackupHandler::default();
        thread::spawn(move || server.run(handler).unwrap());

        Ok(output::Empty::default())
    }
}

/// A server stopper
#[derive(Debug, Clone)]
pub struct ServerStopper;

impl EnclaveEngine for ServerStopper {
    type EI = input::CallServerStopper;
    type EO = output::Empty;

    fn handle<R, C>(
        _ecall_input: Self::EI,
        _enclave_context: &C,
        _max_mem_size: usize,
    ) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        Ok(output::Empty::default())
    }
}
