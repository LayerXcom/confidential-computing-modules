// UnixDomainSocket cannot be used in enclave
use std::net::TcpStream;
use std::io::{Read, BufReader};
use tracing::{error, info, warn};
use anyhow::Result;

pub struct EnclaveService {}

impl EnclaveService {
    pub fn start<S: ToSocketAddrs>(socket_addr: S) -> Result<()> {
        let stream = TcpStream::connect(socket_addr)?;
        let mut reader = BufReader::new(&stream);

        'recv: loop {
            match self.handle_msg() {
                Ok(()) => {}
                Err(err) => {
                    break 'recv;
                }
            }
        }

        warn!("TcpStream Connection with HostService is closed...")

        Ok(())
    }

    fn handle_msg(&self) -> Result<()> {

        Ok(())
    }

    fn decode_msg() {

    }

    fn encode_msg() {}

}
