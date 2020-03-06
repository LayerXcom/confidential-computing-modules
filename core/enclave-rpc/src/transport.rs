use std::net::TcpStream;
use std::io::{Read, Write};
use std::mem::transmute;
use std::vec::Vec;
use anyhow::{Result, ensure};
use log::debug;
use crate::EnclaveHandler;

pub trait ClientTransport {
    fn send(&mut self, req: &[u8]) -> Result<Vec<u8>>;
}

pub trait ServerTransport {
    fn serve<T>(&mut self, handler: T) -> Result<()>
    where
        T: EnclaveHandler;
}

pub struct TlsTransport<S: rustls::Session> {
    stream: rustls::StreamOwned<S, TcpStream>,
}

impl<S: rustls::Session> TlsTransport<S> {
    pub fn new(stream: rustls::StreamOwned<S, TcpStream>) -> Self {
        TlsTransport { stream }
    }
}

impl<S: rustls::Session> ClientTransport for TlsTransport<S> {
    fn send(&mut self, req: &[u8]) -> Result<Vec<u8>> {
        let mut msg = Message::new(&mut self.stream);
        msg.write(req)?;
        msg.read()
    }
}

impl<S: rustls::Session> ServerTransport for TlsTransport<S> {
    fn serve<T>(&mut self, handler: T) -> Result<()>
    where
        T: EnclaveHandler,
    {
        let mut msg = Message::new(&mut self.stream);
        loop {
            let req = match msg.read() {
                Ok(r) => r,
                Err(e) => {
                    debug!("Connection disconnected: {:?}", e);
                    return Ok(());
                }
            };

            let res = handler.handle_req(&req)?;
            msg.write(&res)?;
        }
        Ok(())
    }
}

pub struct Message<'a, T>
where
    T: Read + Write,
{
    transport: &'a mut T,
    max_frame_len: usize,
}

impl<T> Message<'_, T>
where
    T: Read + Write,
{
    pub fn new(transport: &'_ mut T) -> Message<'_, T> {
        Message {
            transport,
            max_frame_len: 8 * 1_024 * 1_024,
        }
    }

    pub fn read(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.transport.read_exact(&mut buf)?;

        ensure!(buf.len() < self.max_frame_len, "Exceed max frame length");

        Ok(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<()>
    {
        self.transport.write_all(&buf)?;
        self.transport.flush()?;

        Ok(())
    }
}
