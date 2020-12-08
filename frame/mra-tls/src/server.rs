use crate::config::ServerConfig;
use crate::connection::Connection;
use anyhow::Result;
use log::error;
use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

pub trait RequestHandler {
    fn handle_json(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

pub struct Server {
    address: String,
    config: ServerConfig,
}

impl Server {
    pub fn new(address: String, config: ServerConfig) -> Self {
        Server { address, config }
    }

    pub fn run<H: RequestHandler + Clone>(&mut self, handler: H) -> Result<()> {
        let listener = std::net::TcpListener::bind(&self.address)?;

        #[cfg(not(test))]
        for stream in listener.incoming() {
            let session = rustls::ServerSession::new(&Arc::new(self.config.tls().clone()));
            match Connection::new(session, stream?).serve_json(handler.clone()) {
                Ok(_) => {}
                Err(e) => error!("{:?}", e),
            }
        }

        #[cfg(test)]
        for stream in listener.incoming().take(1) {
            let session = rustls::ServerSession::new(&Arc::new(self.config.tls().clone()));
            match Connection::new(session, stream?).serve_json(handler.clone()) {
                Ok(_) => {}
                Err(e) => error!("{:?}", e),
            }
        }

        Ok(())
    }
}
