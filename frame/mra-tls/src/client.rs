use crate::config::ClientConfig;
use crate::connection::Connection;
use anonify_config::{REQUEST_RETRIES, RETRY_DELAY_MILLS};
use anyhow::{anyhow, Result};
use frame_retrier::{strategy, Retry};
use http::Uri;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

pub struct Client {
    connection: Connection<rustls::ClientSession>,
}

impl Client {
    pub fn new(address: &str, client_config: &ClientConfig) -> Result<Self> {
        let uri = address.parse::<Uri>()?;
        let hostname = uri.host().ok_or_else(|| anyhow!("Invalid hostname"))?;
        let hostname = webpki::DNSNameRef::try_from_ascii_str(hostname)?;

        let session = rustls::ClientSession::new(&Arc::new(client_config.tls().clone()), hostname);
        let stream = std::net::TcpStream::connect(address)?;
        let connection = Connection::new(session, stream);

        Ok(Client { connection })
    }

    pub fn send_json<SE, DE>(&mut self, json: SE) -> Result<DE>
    where
        SE: Serialize,
        DE: DeserializeOwned,
    {
        let wrt = serde_json::to_vec(&json)?;
        Retry::new(
            "mutual_attested_tls",
            REQUEST_RETRIES,
            strategy::FixedDelay::new(RETRY_DELAY_MILLS),
        )
        .spawn(|| self.connection.write_frame(&wrt))?;

        let rd = self.connection.read_frame()?;
        serde_json::from_slice(&rd).map_err(Into::into)
    }
}
