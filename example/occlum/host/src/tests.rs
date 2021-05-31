use occlum_rpc_types::hello_world::{greeter_client::GreeterClient, HelloRequest};
use std::env;
use tonic_health::proto::{health_client::HealthClient, HealthCheckRequest};

#[tokio::test]
async fn test_health_check() -> Result<(), Box<dyn std::error::Error>> {
    let enclave_ip =
        env::var("OCCLUM_ENCLAVE_IP_ADDRESS").expect("OCCLUM_ENCLAVE_IP_ADDRESS is not set.");
    let enclave_port = env::var("OCCLUM_ENCLAVE_PORT").expect("OCCLUM_ENCLAVE_PORT is not set.");
    let mut client =
        HealthClient::connect(format!("http://{}:{}", enclave_ip, enclave_port)).await?;

    let request = tonic::Request::new(HealthCheckRequest {
        service: "helloworld.Greeter".to_string(),
    });

    let response = client.check(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}

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
