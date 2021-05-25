use anyhow::Result;
use std::net::SocketAddr;
use tonic::body::BoxBody;
use tonic::codegen::{
    http::{Request, Response},
    Service,
};
use tonic::transport::{Body, NamedService, Server};
use tracing::info;

pub struct EnclaveGrpcServer<S> {
    addr: SocketAddr,
    service: S,
}

impl<S> EnclaveGrpcServer<S>
where
    S: Service<Request<Body>, Response = Response<BoxBody>> + NamedService + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    pub fn new(addr: SocketAddr, service: S) -> Self {
        Self { addr, service }
    }

    pub async fn start(self) -> Result<()> {
        info!("EnclaveGrpcServer listening on {}", self.addr);

        Server::builder()
            .add_service(self.service) // TODO: get mutiple
            .serve(self.addr)
            .await?;

        Ok(())
    }
}
