use crate::{Client, ClientConfig, RequestHandler, Server, ServerConfig};
use crate::primitives::pemfile;
use serde_json::Value;
use once_cell::sync::Lazy;
use std::{
    env,
    string::String,
    thread,
    vec::Vec,
};
use test_utils::*;

static SERVER_ADDRESS: Lazy<String> = Lazy::new( || {
    let host = env::var("HOSTNAME").expect("failed to get env 'HOSTNAME'");
    format!("{}:12345", host)
});
const LISTEN_ADDRESS: &str = "0.0.0.0:12345";

const SERVER_PRIVATE_KEY: &'static [u8] = include_bytes!("../certs/localhost.key");
const SERVER_CERTIFICATES: &str = include_str!("../certs/localhost_v3.crt");
const CA_CERTIFICATE: &str = include_str!("../certs/ca_v3.crt");

pub fn run_tests() -> bool {
    check_all_passed!(run_tests!(test_request_response,),)
}

#[derive(Default, Clone)]
struct EchoHandler;

impl RequestHandler for EchoHandler {
    fn handle_json(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
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
    let mut client_config = ClientConfig::default();

    client_config.add_pem_to_root(CA_CERTIFICATE).unwrap();

    Client::new(&*SERVER_ADDRESS, client_config).unwrap()
}

fn start_server() {
    let private_keys = pemfile::rsa_private_keys(&mut SERVER_PRIVATE_KEY).unwrap();
    let certs = pemfile::certs(&mut SERVER_CERTIFICATES.as_bytes()).unwrap();
    let mut server_config = ServerConfig::default();
    server_config
        .set_single_cert(&certs, &private_keys.first().unwrap())
        .unwrap();

    let mut server = Server::new(LISTEN_ADDRESS, server_config);
    let handler = EchoHandler::default();
    thread::spawn(move || server.run(handler).unwrap());
}
