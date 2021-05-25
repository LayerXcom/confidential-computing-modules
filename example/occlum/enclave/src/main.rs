use handler::MyGreeter;
use occlum_enclave::service::EnclaveGrpcServer;
use occlum_rpc_types::hello_world::greeter_server::GreeterServer;
mod handler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "172.16.15.2:50051".parse().unwrap();
    let test_service = GreeterServer::new(MyGreeter::default());

    EnclaveGrpcServer::new(addr, test_service).start().await?;

    Ok(())
}
