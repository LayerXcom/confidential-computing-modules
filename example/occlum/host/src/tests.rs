use occlum_rpc_types::hello_world::{greeter_client::GreeterClient, HelloRequest};
use std::env;

#[tokio::test]
async fn test_hello() -> Result<(), Box<dyn std::error::Error>> {
    let enclave_ip =
        env::var("OCCLUM_ENCLAVE_IP_ADDRESS").expect("OCCLUM_ENCLAVE_IP_ADDRESS is not set.");
    let enclave_port = env::var("OCCLUM_ENCLAVE_PORT").expect("OCCLUM_ENCLAVE_PORT is not set.");
    let mut client =
        GreeterClient::connect(format!("http://{}:{}", enclave_ip, enclave_port)).await?;

    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
