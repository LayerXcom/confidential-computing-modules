use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::vec::Vec;
use crate::server::RequestHandler;

pub struct Connection<S: rustls::Session> {
    stream: rustls::StreamOwned<S, TcpStream>,
    max_frame_len: u64,
}

impl<S: rustls::Session> Connection<S> {
    pub fn new(sess: S, sock: TcpStream, max_frame_len: u64) -> Self {
        Connection {
            stream: rustls::StreamOwned::new(sess, sock),
            max_frame_len,
        }
    }

    pub fn read_frame<DE>(&mut self) -> Result<DE>
    where
        DE: DeserializeOwned,
    {
        let mut header = [0u8; 8];

        self.stream.read_exact(&mut header)?;
        let buf_len = u64::from_be_bytes(header);
        ensure!(buf_len <= self.max_frame_len, "Exceed max frame length");

        let mut buf = Vec::with_capacity(buf_len as usize);
        self.stream.read_exact(&mut buf)?;

        serde_json::from_slice(&buf).map_err(Into::into)
    }

    pub fn write_frame<SE>(&mut self, message: SE) -> Result<()>
    where
        SE: Serialize,
    {
        let buf = serde_json::to_vec(&message)?;
        let buf_len = buf.len() as u64;
        let header = buf_len.to_be_bytes();

        self.stream.write(&header)?;
        self.stream.write_all(&buf)?;
        self.stream.flush()?;

        Ok(())
    }

    pub fn serve<H: RequestHandler>(&mut self, handler: H) -> Result<()> {
        loop {
            let request = self.read_frame()?;
            let response = handler.handle(&request)?;
            self.write_frame(response)?;
        }
    }
}
