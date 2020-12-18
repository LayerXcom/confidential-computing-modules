use crate::error::MraTLSError;
use crate::primitives::{Certificate, PrivateKey};
use anyhow::anyhow;
use std::{sync::Arc, vec::Vec};

#[derive(Clone)]
pub struct ClientConfig {
    tls: rustls::ClientConfig,
}

impl ClientConfig {
    pub fn tls(&self) -> &rustls::ClientConfig {
        &self.tls
    }

    pub fn add_pem_to_root(&mut self, ca_cert: &str) -> Result<(), MraTLSError> {
        let (_, invalid_count) = self
            .tls
            .root_store
            .add_pem_file(&mut ca_cert.as_bytes())
            .map_err(|e| anyhow!("failed to add pem file: {:?}", e))?;

        if invalid_count > 0 {
            return Err(anyhow!("invalid_count").into());
        }

        Ok(())
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        let mut client_tls_config = rustls::ClientConfig::new();

        client_tls_config
            .dangerous()
            .set_certificate_verifier(NoServerVerify::new());

        client_tls_config.versions.clear();
        client_tls_config
            .versions
            .push(rustls::ProtocolVersion::TLSv1_3);

        Self {
            tls: client_tls_config,
        }
    }
}

pub struct ServerConfig {
    tls: rustls::ServerConfig,
}

impl ServerConfig {
    pub fn tls(&self) -> &rustls::ServerConfig {
        &self.tls
    }

    pub fn set_single_cert(
        &mut self,
        cert_chain: &Vec<Certificate>,
        key_der: &PrivateKey,
    ) -> Result<(), MraTLSError> {
        let certs = cert_chain.iter().map(|cert| cert.as_rustls()).collect();

        self.tls
            .set_single_cert(certs, key_der.as_rustls())
            .map_err(Into::into)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        let client_tls = rustls::NoClientAuth::new();
        let server_tls = rustls::ServerConfig::new(client_tls);

        Self { tls: server_tls }
    }
}

struct NoServerVerify;

impl NoServerVerify {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<dyn rustls::ServerCertVerifier> {
        Arc::new(NoServerVerify)
    }
}

impl rustls::ServerCertVerifier for NoServerVerify {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef<'_>,
        _ocsp: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}
