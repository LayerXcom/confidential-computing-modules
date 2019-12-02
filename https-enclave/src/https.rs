use std::{
    prelude::v1::*,
    io::{self, Write},
    net::{ToSocketAddrs},
};
use crate::client::{create_client_config, TlsClient};
use crate::error::Result;
use mio::net::TcpStream;

pub struct HttpsClient(TlsClient);

const HTTPS_DEFAULT_PORT: u16 = 443;
const DEFAULT_EVENTS_CAPACITY: usize = 32;

impl HttpsClient {
    pub fn new(hostname: &str, cert: &str) -> Result<Self> {
        let config = create_client_config(cert)?;
        let mut addrs_iter = (hostname, HTTPS_DEFAULT_PORT).to_socket_addrs()?;
        let socket_addr = addrs_iter.next().unwrap();
        assert_eq!(addrs_iter.next(), None);

        let socket = TcpStream::connect(&socket_addr)?;
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

    pub fn send_from_raw_req(&mut self, req: String) -> Result<Vec<u8>> {
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
