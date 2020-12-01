use std::sync::Arc;

#[derive(Clone)]
pub struct ClientConfig {
    tls: rustls::ClientConfig,
}

impl ClientConfig {
    pub fn tls(&self) -> &rustls::ClientConfig {
        &self.tls
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        let mut client_tls_config = rustls::ClientConfig::new();

        client_tls_config
            .dangerous()
            .set_certificate_verifier(NoServerVerify::new());

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
