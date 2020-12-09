use crate::server::RequestHandler;
use anyhow::{ensure, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::vec::Vec;

const MAX_FRAME_LEN: u64 = 2048;

pub struct Connection<S: rustls::Session> {
    stream: rustls::StreamOwned<S, TcpStream>,
    max_frame_len: u64,
}

impl<S: rustls::Session> Connection<S> {
    pub fn new(sess: S, sock: TcpStream) -> Self {
        Connection {
            stream: rustls::StreamOwned::new(sess, sock),
            max_frame_len: MAX_FRAME_LEN,
        }
    }

    pub fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut header = [0u8; 8];
        self.stream.read_exact(&mut header)?;
        let frame_len = u64::from_be_bytes(header);

        ensure!(frame_len <= self.max_frame_len, "Exceed max frame length");

        let mut frame = vec![0u8; frame_len as usize];
        self.stream.read_exact(&mut frame)?;

        Ok(frame)
    }

    pub fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        let frame_len = frame.len() as u64;
        let header = frame_len.to_be_bytes();

        self.stream.write(&header)?;
        self.stream.write_all(&frame)?;
        self.stream.flush()?;

        Ok(())
    }

    pub fn serve_json<H: RequestHandler>(&mut self, handler: H) -> Result<()> {
        let req = self.read_frame().unwrap();
        if req.len() == 0 {
            dbg!("request's length is 0");
            return Ok(());
        }
        let resp = handler.handle_json(&req)?;
        self.write_frame(resp)?;
        Ok(())
    }
}
