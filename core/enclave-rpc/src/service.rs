use crate::config::RuntimeConfig;
use crate::server::Server;
use crate::config::{ClientConfig, ServerConfig};
use anyhow::Result;

pub struct Service;

impl Service {
    pub fn start(config: &RuntimeConfig) -> Result<()> {
        let client_config = ClientConfig::new();
        let server_config = ServerConfig::new();
        let mut server = Server::new(config.listen_addr, server_config);


        Ok(())
    }
}


pub struct Client;
