use crate::handler::*;
use anyhow::Result;
use occlum_rpc_types::hello_world::greeter_server::GreeterServer;
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::info;

pub struct EnclaveService {
    addr: SocketAddr,
}

impl EnclaveService {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn start(self) -> Result<()> {
        let greeter = MyGreeter::default();

        info!("GreeterServer listening on {}", self.addr);

        Server::builder()
            .add_service(GreeterServer::new(greeter))
            .serve(self.addr)
            .await?;

        Ok(())
    }
}
