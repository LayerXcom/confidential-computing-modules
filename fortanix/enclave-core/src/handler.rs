use anyhow::Result;
use frame_schema::{Body, EnclaveMessage, MessageType};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use tracing::{error, info, warn};

pub struct EnclaveHandler {
    stream: TcpStream,
}

impl EnclaveHandler {
    // UnixDomainSocket cannot be used in enclave
    pub fn connect<S: ToSocketAddrs>(socket_addr: S) -> Result<Self> {
        let stream = TcpStream::connect(socket_addr)?;
        Ok(Self { stream })
    }

    pub fn start(&self) -> Result<()> {
        let mut reader = BufReader::new(&self.stream);

        'recv: loop {
            match self.handle_msg(&mut reader) {
                Ok(()) => {}
                Err(err) => {
                    break 'recv;
                }
            }
        }

        warn!("TcpStream Connection with HostService is closed...");

        Ok(())
    }

    fn handle_msg<R: Read>(&self, reader: R) -> Result<()> {
        let msg = EnclaveMessage::decode_msg(reader)?;
        match msg.message_type {
            MessageType::Request => {
                // TODO: add tracing

                let resp_body = Self::handle_request(msg.body)?;
                let resp_msg =
                    EnclaveMessage::new(msg.id, MessageType::Response, resp_body, msg.span_context);
                self.write_msg(resp_msg)?;
            }
            MessageType::Response => {}
        }

        Ok(())
    }

    fn handle_request(body: Body) -> Result<Body> {
        match body {
            Body::Test { test } => {
                println!("Hello World: {}", test);
                Ok(Body::Test { test })
            }
        }
    }

    fn write_msg(&self, msg: EnclaveMessage) -> Result<()> {
        let mut writer = BufWriter::new(&self.stream);
        let buffer = serde_cbor::to_vec(&msg)?;

        // TODO: check message size

        writer.write_all(&buffer)?;

        Ok(())
    }
}
