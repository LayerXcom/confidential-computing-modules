use handler::MyGreeter;
use occlum_enclave::service::EnclaveGrpcServer;
use occlum_rpc_types::hello_world::greeter_server::GreeterServer;
use std::env;
mod handler;

// TODO: Move to test. Test binaries can be executable in encalave.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let enclave_ip =
        env::var("OCCLUM_ENCLAVE_IP_ADDRESS").expect("OCCLUM_ENCLAVE_IP_ADDRESS is not set.");
    let enclave_port = env::var("OCCLUM_ENCLAVE_PORT").expect("OCCLUM_ENCLAVE_PORT is not set.");

    let addr = format!("{}:{}", enclave_ip, enclave_port).parse().unwrap();
    let test_service = GreeterServer::new(MyGreeter::default());

    EnclaveGrpcServer::new(addr, test_service).start().await?;

    Ok(())
}
