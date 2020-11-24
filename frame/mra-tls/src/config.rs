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
        let tls = rustls::ClientConfig::new();

        Self { tls }
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

struct NoServerAuth;

impl rustls::ServerCertVerifier for NoServerAuth {
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
