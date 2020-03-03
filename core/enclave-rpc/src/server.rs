use std::net::{SocketAddr, TcpListener};
use anyhow::{Result, anyhow};
use log::{debug, error, warn};
use crate::config::ServerConfig;
use crate::transport::{TlsTransport, ServerTransport};

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

    pub fn start(&mut self) -> Result<()> {
        let listener = TcpListener::bind(self.addr)?;
        let tls_config = self.config.tls_config();
        let pool = threadpool::ThreadPool::new(1);
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let session = rustls::ServerSession::new(&tls_config);
                    let stream = rustls::StreamOwned::new(session, stream);
                    let mut transport = TlsTransport::new(stream);

                    pool.execute(move || match transport.serve() {
                        Ok(_) => (),
                        Err(e) => debug!("serve error: {:?}", e),
                    });
                }
                Err(e) => error!("Incoming error: {:}", e),
            }
        }
        Ok(())
    }
}
