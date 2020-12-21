use crate::error::{MraTLSError, Result};
use crate::key::NistP256KeyPair;
use crate::verifier::AttestationReportVerifier;
use anyhow::anyhow;
use remote_attestation::QuoteTarget;
use sgx_types::sgx_spid_t;
use std::{sync::Arc, vec::Vec};

const CERT_ISSUER: &str = "Anonify";
const CERT_SUBJECT: &str = "CN=Anonify";

#[derive(Debug)]
pub struct AttestedTlsConfig {
    ee_cert: Vec<u8>,
    priv_key: Vec<u8>,
}

impl AttestedTlsConfig {
    fn remote_attestation(spid: sgx_spid_t, ias_url: &str, sub_key: &str) -> Result<Self> {
        let key_pair = NistP256KeyPair::new()?;
        let report_data = key_pair.report_data();
        let resp = QuoteTarget::new()?
            .set_enclave_report(&report_data)?
            .create_quote(&spid)?
            .remote_attestation(ias_url, sub_key)?;

        let extension = serde_json::to_vec(&resp)?;
        let ee_cert = key_pair.create_cert_with_extension(CERT_ISSUER, CERT_SUBJECT, &extension);
        let priv_key = key_pair.priv_key_into_der();

        Ok(Self { ee_cert, priv_key })
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    tls: rustls::ClientConfig,
}

impl ClientConfig {
    pub fn tls(&self) -> &rustls::ClientConfig {
        &self.tls
    }

    pub fn add_pem_to_root(&mut self, ca_cert: &str) -> Result<()> {
        let (_, invalid_count) = self
            .tls
            .root_store
            .add_pem_file(&mut ca_cert.as_bytes())
            .map_err(|e| anyhow!("failed to add pem file: {:?}", e))?;

        if invalid_count > 0 {
            return Err(MraTLSError::Error(anyhow!("invalid_count")));
        }

        Ok(())
    }

    pub fn set_attestation_report_verifier(mut self, root_cert: Vec<u8>) -> Self {
        let verifier = Arc::new(AttestationReportVerifier::new(root_cert));
        self.tls.dangerous().set_certificate_verifier(verifier);

        self
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
        cert_chain: Vec<rustls::Certificate>,
        key_der: rustls::PrivateKey,
    ) -> Result<()> {
        self.tls
            .set_single_cert(cert_chain, key_der)
            .map_err(Into::into)
    }

    pub fn set_attestation_report_verifier(mut self, root_cert: Vec<u8>) -> Self {
        let verifier = Arc::new(AttestationReportVerifier::new(root_cert));
        self.tls.set_client_certificate_verifier(verifier);

        self
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
    ) -> std::result::Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}
