use occlum_enclave::EnclaveGrpcServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "172.16.15.2:50051".parse().unwrap();
    let test_service = GreeterServer::new(MyGreeter::default());

    EnclaveGrpcServer::new(addr, test_service).start().await?;
}
