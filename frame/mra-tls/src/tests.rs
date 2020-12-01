use crate::{Client, ClientConfig, RequestHandler, Server, ServerConfig};
use anyhow::Result;
use serde_json::Value;
use std::string::{String, ToString};
use std::thread;
use std::vec::Vec;
use test_utils::*;

const CLIENT_ADDRESS: &str = "localhost:12345";
const SERVER_ADDRESS: &str = "127.0.0.1:12345";

pub fn run_tests() -> bool {
    check_all_passed!(run_tests!(test_request_response,),)
}

#[derive(Default, Clone)]
struct EchoHandler;

impl RequestHandler for EchoHandler {
    fn handle_json(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let msg_json: Value = serde_json::from_slice(&msg)?;
        // assert_eq!(msg_json["message"], b"Hello test_request_response");
        serde_json::to_vec(&msg_json).map_err(Into::into)
    }
}

fn test_request_response() {
    start_server();

    let msg = r#"{
        "message": "Hello test_request_response"
    }"#;
    let client_config = ClientConfig::default();
    let mut client = Client::new(CLIENT_ADDRESS, client_config).unwrap();
    let resp: String = client.send_json(msg).unwrap();

    assert_eq!(msg, resp);
}

fn start_server() {
    let config = ServerConfig::default();
    let mut server = Server::new(SERVER_ADDRESS.to_string(), config);
    let handler = EchoHandler::default();
    server.run(handler).unwrap();
}
