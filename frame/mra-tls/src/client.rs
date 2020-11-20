use crate::config::ClientConfig;
use crate::connection::Connection;
use anyhow::{anyhow, Result};
use http::Uri;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

pub struct Client {
    connection: Connection<rustls::ClientSession>,
}

impl Client {
    pub fn new(address: &str, client_config: ClientConfig, max_frame_len: u64) -> Result<Self> {
        let uri = address.parse::<Uri>()?;
        let hostname = uri.host().ok_or_else(|| anyhow!("Invalid hostname"))?;
        let hostname = webpki::DNSNameRef::try_from_ascii_str(hostname)?;

        let session = rustls::ClientSession::new(&Arc::new(client_config.tls().clone()), hostname);
        let stream = std::net::TcpStream::connect(address)?;
        let connection = Connection::new(session, stream, max_frame_len);

        Ok(Client { connection })
    }

    pub fn request<SE, DE>(&mut self, message: SE) -> Result<DE>
    where
        SE: Serialize,
        DE: DeserializeOwned,
    {
        self.connection.write_frame(message)?;
        self.connection.read_frame()
    }
}
