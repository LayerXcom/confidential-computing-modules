use crate::config::ServerConfig;
use crate::connection::Connection;
use anyhow::Result;
use log::error;
use serde::{de::DeserializeOwned, Serialize};
use std::string::String;
use std::sync::Arc;

pub trait RequestHandler {
    fn handle<SE, DE>(&self, message: SE) -> Result<DE>
    where
        SE: Serialize,
        DE: DeserializeOwned;
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
        for stream in listener.incoming() {
            let session = rustls::ServerSession::new(&Arc::new(self.config.tls().clone()));
            match Connection::new(session, stream?).serve(handler.clone()) {
                Ok(_) => {}
                Err(e) => error!("{:?}", e),
            }
        }

        Ok(())
    }
}
