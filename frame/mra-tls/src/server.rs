use crate::config::ServerConfig;
use crate::connection::Connection;
use anyhow::{anyhow, Result};
use log::error;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::vec::Vec;

pub trait RequestHandler {
    fn handle(&self, ) -> Result<Vec<u8>>;
}

pub struct Server {
    connection: Connection<rustls::ServerSession>,
    address: std::net::SocketAddr,
    config: ServerConfig,
    max_frame_len: u64,
}

impl Server {
    pub fn new(address: &str) -> Self {
        unimplemented!();
    }

    pub fn run<H: RequestHandler + Clone>(&mut self, handler: H) -> Result<()> {
        let tls_config = self.config.tls();

        let listener = std::net::TcpListener::bind(self.address)?;
        for stream in listener.incoming() {
            let session = rustls::ServerSession::new(&Arc::new(self.config.tls().clone()));
            match Connection::new(session, stream?, self.max_frame_len).serve(handler.clone()) {
                Ok(_) => {}
                Err(e) => error!("{:?}", e),
            }
        }

        Ok(())
    }
}
