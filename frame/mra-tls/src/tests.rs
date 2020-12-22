use crate::{Client, ClientConfig, RequestHandler, Server, ServerConfig};
use anonify_config::IAS_ROOT_CERT;
use anyhow::Result;
use serde_json::Value;
use std::{
    string::{String, ToString},
    thread,
    vec::Vec,
    time::Duration,
};
use test_utils::*;

const CLIENT_ADDRESS: &str = "localhost:12345";
const SERVER_ADDRESS: &str = "0.0.0.0:12345";

pub fn run_tests() -> bool {
    check_all_passed!(
        run_tests!(test_request_response,),
        crate::key::tests::run_tests(),
    )
}

#[derive(Default, Clone)]
struct EchoHandler;

impl RequestHandler for EchoHandler {
    fn handle_json(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let msg_json: Value = serde_json::from_slice(&msg)?;
        serde_json::to_vec(&msg_json).map_err(Into::into)
    }
}

fn test_request_response() {
    start_server();
    let mut client = build_client();

    let msg = r#"{
        "message": "Hello test_request_response"
    }"#;
    let resp: String = client.send_json(msg).unwrap();

    assert_eq!(msg, resp);
}

fn build_client() -> Client {
    let client_config =
        ClientConfig::default().set_attestation_report_verifier(IAS_ROOT_CERT.to_vec());

    Client::new(CLIENT_ADDRESS, client_config).unwrap()
}

fn start_server() {
    let server_config =
        ServerConfig::default().set_attestation_report_verifier(IAS_ROOT_CERT.to_vec());

    let mut server = Server::new(SERVER_ADDRESS.to_string(), server_config);
    let handler = EchoHandler::default();
    thread::spawn(move || server.run(handler).unwrap());
    thread::sleep(Duration::from_secs(1));
}
