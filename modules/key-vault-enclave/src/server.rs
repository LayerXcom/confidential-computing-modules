use crate::handlers::KeyVaultHandler;
use anonify_config::{ENCLAVE_MEASUREMENT_ERC20, IAS_ROOT_CERT};
use anonify_io_types::*;
use frame_common::state_types::StateType;
use frame_enclave::EnclaveEngine;
use frame_mra_tls::{AttestedTlsConfig, Server, ServerConfig};
use frame_runtime::traits::*;
use std::{string::ToString, thread};

const SERVER_ADDRESS: &str = "0.0.0.0:12345";

/// A server starter
#[derive(Debug, Clone)]
pub struct ServerStarter;

impl EnclaveEngine for ServerStarter {
    type EI = input::CallServerStarter;
    type EO = output::Empty;

    fn handle_without_runtime<C>(enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter,
    {
        let ias_url = enclave_context.ias_url();
        let sub_key = enclave_context.sub_key();
        let spid = enclave_context.spid();

        let attested_tls_config =
            AttestedTlsConfig::new_by_ra(&spid, &ias_url, &sub_key, IAS_ROOT_CERT.to_vec())?;

        let server_config = ServerConfig::from_attested_tls_config(attested_tls_config)?
            .set_attestation_report_verifier(IAS_ROOT_CERT.to_vec(), *ENCLAVE_MEASUREMENT_ERC20);

        let mut server = Server::new(SERVER_ADDRESS.to_string(), server_config);
        let handler = KeyVaultHandler::default();
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
