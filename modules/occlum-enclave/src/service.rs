use crate::context::OcclumEnclaveContext;
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
    context: OcclumEnclaveContext,
}

impl<S> EnclaveGrpcServer<S>
where
    S: Service<Request<Body>, Response = Response<BoxBody>> + NamedService + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    pub fn new(addr: SocketAddr, service: S) -> Self {
        let context = OcclumEnclaveContext::new();
        Self {
            addr,
            service,
            context,
        }
    }

    pub async fn start(self) -> Result<()> {
        // TODO: Add RA
        // let report = self.context.do_remote_attestation()?;
        // println!("Remote attested report: {:?}", report);

        info!("EnclaveGrpcServer listening on {}", self.addr);
        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter.set_serving::<S>().await;

        Server::builder()
            .add_service(health_service)
            .add_service(self.service) // TODO: get mutiple
            .serve(self.addr)
            .await?;

        Ok(())
    }
}
