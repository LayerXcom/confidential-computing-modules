use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::Result;

#[derive(Clone)]
pub struct ServerConfig {
    tls_config: rustls::ServerConfig
}

impl ServerConfig {
    pub fn new() -> Self {
        let client_cert_verifier = rustls::NoClientAuth::new();
        let tls_config = rustls::ServerConfig::new(client_cert_verifier);

        ServerConfig {
            tls_config,
        }
    }

    pub fn server_cert(mut self, cert: &[u8], key_der: &[u8]) -> Result<Self> {
        let cert_chain = vec![rustls::Certificate(cert.to_vec())];
        let key_der = rustls::PrivateKey(key_der.to_vec());
        self.tls_config.set_single_cert(cert_chain, key_der)?;

        Ok(ServerConfig { ..self })
    }

    pub fn tls_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::new(self.tls_config.clone())
    }
}

pub struct ClientConfig {
    config: rustls::ClientConfig,
}

impl ClientConfig {
    pub fn new() -> Self {
        let config = rustls::ClientConfig::new();

        ClientConfig { config }
    }

    pub fn config_arc(&self) -> Arc<rustls::ClientConfig> {
        Arc::new(self.config.clone())
    }
}

pub struct RuntimeConfig {
    pub listen_addr: SocketAddr,
}
