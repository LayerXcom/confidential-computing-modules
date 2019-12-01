use std::{
    prelude::v1::*,
    io::{Read, Write},
    sync::Arc,
};
use mio::net::TcpStream;
use rustls::{ClientSession, ClientConfig};


/// A synchronous client to make requests with.
pub struct TlsClient {
    socket: TcpStream,
    session: rustls::ClientSession,
}

impl TlsClient {
    pub fn new(
        socket: TcpStream,
        hostname: webpki::DNSNameRef,
        cfg: Arc<ClientConfig>
    ) -> TlsClient {
        TlsClient {
            socket,
            session: ClientSession::new(&cfg, hostname),
        }
    }
}
