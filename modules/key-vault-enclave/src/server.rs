use crate::handlers::BackupHandler;
use anonify_io_types::*;
use anyhow::anyhow;
use frame_common::state_types::StateType;
use frame_enclave::EnclaveEngine;
use frame_mra_tls::{primitives::pemfile, Server, ServerConfig};
use frame_runtime::traits::*;
use std::thread;

const SERVER_ADDRESS: &str = "0.0.0.0:12345";

const SERVER_PRIVATE_KEY: &'static [u8] =
    include_bytes!("../../../frame/mra-tls/certs/localhost.key");
const SERVER_CERTIFICATES: &str = include_str!("../../../frame/mra-tls/certs/localhost_v3.crt");

/// A server starter
#[derive(Debug, Clone)]
pub struct ServerStarter;

impl EnclaveEngine for ServerStarter {
    type EI = input::CallServerStarter;
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
        let certificates = pemfile::certs(&mut SERVER_CERTIFICATES.as_bytes())
            .map_err(|_| anyhow!("failed to extract certificates"))?;
        let private_key = pemfile::rsa_private_keys(&mut SERVER_PRIVATE_KEY)
            .map_err(|_| anyhow!("failed to extract RSA private key"))?;
        let mut server_config = ServerConfig::default();
        server_config.set_single_cert(
            &certificates,
            private_key
                .first()
                .ok_or_else(|| anyhow!("private_key is unset"))?,
        )?;

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
