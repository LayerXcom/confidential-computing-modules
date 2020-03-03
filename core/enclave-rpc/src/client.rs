use crate::config::ClientConfig;
use crate::transport::{TlsTransport, ClientTransport};
use anyhow::{Result, anyhow};
use http::Uri;
use webpki::DNSNameRef;
use std::net::TcpStream;
use std::vec::Vec;

pub struct TlsClient {
    transport: TlsTransport<rustls::ClientSession>
}

impl TlsClient {
    pub fn new(addr: &str, config: &ClientConfig) -> Result<Self> {
        let uri = addr.parse::<Uri>()?;
        let host = uri.host().ok_or_else(|| anyhow!("Invalid hostname"))?;
        let stream = TcpStream::connect(addr)?;
        let hostname = DNSNameRef::try_from_ascii_str(host)?;
        let sess = rustls::ClientSession::new(&config.config_arc(), hostname);
        let stream = rustls::StreamOwned::new(sess, stream);
        let transport = TlsTransport::new(stream);

        Ok(TlsClient { transport })
    }

    pub fn send(&mut self, req: &[u8]) -> Result<Vec<u8>> {
        self.transport.send(req)
    }
}
