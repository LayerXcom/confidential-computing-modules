use std::net::{SocketAddr, TcpListener};
use anyhow::{Result, anyhow};
use log::{debug, error, warn};
use crate::config::ServerConfig;
use crate::transport::{TlsTransport, ServerTransport};
use crate::EnclaveHandler;

pub struct Server {
    addr: SocketAddr,
    config: ServerConfig,
}

impl Server {
    pub fn new(addr: SocketAddr, config: ServerConfig) -> Self {
        Server {
            addr, config,
        }
    }

    pub fn start<T>(&mut self, handler: T) -> Result<()>
    where
        T: EnclaveHandler + Clone + core::marker::Send + 'static,
    {
        let listener = TcpListener::bind(self.addr)?;
        let tls_config = self.config.tls_config();
        let pool = threadpool::ThreadPool::new(1);
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let session = rustls::ServerSession::new(&tls_config);
                    let stream = rustls::StreamOwned::new(session, stream);
                    let mut transport = TlsTransport::new(stream);
                    let handler = handler.clone();
                    pool.execute(move || match transport.serve(handler) {
                        Ok(_) => (),
                        Err(e) => debug!("serve error: {:?}", e),
                    });
                }
                Err(e) => error!("Incoming error: {:?}", e),
            }
        }
        Ok(())
    }
}
