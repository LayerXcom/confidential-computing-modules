use std::{
    prelude::v1::*,
    io::{self, Write, Read},
    net::{TcpStream as stdTcpStream, ToSocketAddrs},
    str
};
use crate::client::{create_client_config, TlsClient};
use crate::error::Result;
use mio::net::TcpStream as mioTcpStream;

pub struct HttpsClient(TlsClient);

const HTTPS_DEFAULT_PORT: u16 = 443;
const DEFAULT_EVENTS_CAPACITY: usize = 32;

impl HttpsClient {
    pub fn new(stream: stdTcpStream, hostname: &str) -> Result<Self> {
        let config = create_client_config()?;
        let socket = mioTcpStream::from_stream(stream)?;
        let client = TlsClient::new(socket, hostname, config)?;

        Ok(HttpsClient(client))
    }

    pub fn get(&self, req: &str) {
        unimplemented!();
    }

    pub fn post(&self, req: &str) {
        unimplemented!();
    }

    pub fn header(&self) {
        unimplemented!();
    }

    pub fn json(&self) {
        unimplemented!();
    }

    pub fn send(&self) {
        unimplemented!();
    }

    pub fn send_from_raw_req(&mut self, req: &str) -> Result<Vec<u8>> {
        self.0.write_all(req.as_bytes())?;
        let mut poll = mio::Poll::new()?;
        let mut events = mio::Events::with_capacity(DEFAULT_EVENTS_CAPACITY);
        self.0.register(&mut poll);
        let mut res = vec![];
        'outer: loop {
            poll.poll(&mut events, None)?;
            for ev in &events {
                if !self.0.ready(&mut poll, &ev, &mut res) {
                    break 'outer;
                }
            }
        }

        Ok(res)
    }
}


//
// temporary implementations
//

pub fn get_report_response(socket: &mut stdTcpStream, req: String) -> Result<Vec<u8>> {
    let config = create_client_config()?;
    let dns_name = webpki::DNSNameRef::try_from_ascii_str("api.trustedservices.intel.com")?;
    let mut sess = rustls::ClientSession::new(&config, dns_name);
    let mut tls = rustls::Stream::new(&mut sess, socket);
    tls.write_all(req.as_bytes())?;
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext)?;

    Ok(plaintext)
}
