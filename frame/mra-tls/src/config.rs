pub struct ClientConfig {
    tls: rustls::ClientConfig,
}

impl ClientConfig {
    pub fn tls(&self) -> &rustls::ClientConfig {
        &self.tls
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
