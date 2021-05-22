use crate::handlers::KeyVaultHandler;
use frame_config::{ANONIFY_ENCLAVE_MEASUREMENT, IAS_ROOT_CERT};
use frame_enclave::BasicEnclaveEngine;
use frame_mra_tls::{AttestedTlsConfig, Server, ServerConfig};
use frame_runtime::traits::*;
use key_vault_ecall_types::*;
use std::env;

/// A server starter
#[derive(Debug, Clone, Default)]
pub struct ServerStarter;

impl BasicEnclaveEngine for ServerStarter {
    type EI = input::CallServerStarter;
    type EO = output::Empty;

    fn handle<C>(self, enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter,
    {
        let ias_url = enclave_context.ias_url();
        let sub_key = enclave_context.sub_key();
        let spid = enclave_context.spid();

        let attested_tls_config =
            AttestedTlsConfig::new_by_ra(&spid, &ias_url, &sub_key, IAS_ROOT_CERT.to_vec())?;

        let server_config = ServerConfig::from_attested_tls_config(attested_tls_config)?
            .set_attestation_report_verifier(IAS_ROOT_CERT.to_vec(), *ANONIFY_ENCLAVE_MEASUREMENT);

        let key_vault_address = env::var("KEY_VAULT_ENDPOINT_FOR_KEY_VAULT")?;
        let mut server = Server::new(key_vault_address, server_config);
        let store_path_secrets = enclave_context.store_path_secrets();
        let store_enclave_dec_key = enclave_context.store_enclave_dec_key();
        let handler =
            KeyVaultHandler::new(store_path_secrets.clone(), store_enclave_dec_key.clone());
        server.run(handler).unwrap();

        Ok(output::Empty::default())
    }
}

/// A server stopper
#[derive(Debug, Clone, Default)]
pub struct ServerStopper;

impl BasicEnclaveEngine for ServerStopper {
    type EI = input::CallServerStopper;
    type EO = output::Empty;

    fn handle<C>(self, _enclave_context: &C) -> anyhow::Result<Self::EO>
    where
        C: ConfigGetter,
    {
        Ok(output::Empty::default())
    }
}
