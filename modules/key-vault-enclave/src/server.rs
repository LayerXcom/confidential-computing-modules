use crate::handlers::KeyVaultHandler;
use frame_config::{ANONIFY_ENCLAVE_MEASUREMENT, IAS_ROOT_CERT};
use frame_enclave::BasicEnclaveUseCase;
use frame_mra_tls::{AttestedTlsConfig, Server, ServerConfig};
use frame_runtime::traits::*;
use key_vault_ecall_types::*;
use std::env;

/// A server starter
#[derive(Debug, Clone)]
pub struct ServerStarter<'c, C> {
    enclave_context: &'c C,
}

impl<'c, C> BasicEnclaveUseCase<'c, C> for ServerStarter<'c, C>
where
    C: ConfigGetter,
{
    type EI = input::CallServerStarter;
    type EO = output::Empty;

    fn new(_enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self> {
        Ok(Self { enclave_context })
    }

    fn run(self) -> anyhow::Result<Self::EO> {
        let ias_url = self.enclave_context.ias_url();
        let sub_key = self.enclave_context.sub_key();
        let spid = self.enclave_context.spid();

        let attested_tls_config =
            AttestedTlsConfig::new_by_ra(&spid, &ias_url, &sub_key, IAS_ROOT_CERT.to_vec())?;

        let server_config = ServerConfig::from_attested_tls_config(attested_tls_config)?
            .set_attestation_report_verifier(IAS_ROOT_CERT.to_vec(), *ANONIFY_ENCLAVE_MEASUREMENT);

        let key_vault_address = env::var("KEY_VAULT_ENDPOINT_FOR_KEY_VAULT")?;
        let mut server = Server::new(key_vault_address, server_config);
        let store_path_secrets = self.enclave_context.store_path_secrets();
        let store_enclave_dec_key = self.enclave_context.store_enclave_dec_key();
        let handler =
            KeyVaultHandler::new(store_path_secrets.clone(), store_enclave_dec_key.clone());
        server.run(handler).unwrap();

        Ok(output::Empty::default())
    }
}

/// A server stopper
#[derive(Debug, Clone)]
pub struct ServerStopper<'c, C> {
    enclave_context: &'c C,
}

impl<'c, C> BasicEnclaveUseCase<'c, C> for ServerStopper<'c, C>
where
    C: ConfigGetter,
{
    type EI = input::CallServerStopper;
    type EO = output::Empty;

    fn new(_enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self> {
        Ok(Self { enclave_context })
    }

    fn run(self) -> anyhow::Result<Self::EO> {
        Ok(output::Empty::default())
    }
}
