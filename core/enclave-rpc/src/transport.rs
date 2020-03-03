use std::net::TcpStream;
use std::io::{Read, Write};
use serde::{Serialize, Deserialize};
use anyhow::Result;

pub trait ClientTransport {
    fn send(&mut self, request)
}

pub trait ServerTransport {

}

pub struct TlsTransport<S: rustls::Session> {
    stream: rustls::StreamOwned<S, TcpStream>,
}

impl<S: rustls::Session> TlsTransport<S> {
    pub fn new(stream: rustls::StreamOwned<S, TcpStream>) -> Self {
        TlsTransport { stream }
    }
}

pub struct Message<'a, T>
where
    T: Read + Write,
{
    transport: &'a mut T,
    max_frame_len: u64,
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

    // pub fn read<D>(&mut self) -> Result<D> {

    // }
}