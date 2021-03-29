use crate::{AttestedTlsConfig, Client, ClientConfig, RequestHandler, Server, ServerConfig};
use anyhow::Result;
use frame_config::{ENCLAVE_MEASUREMENT, IAS_ROOT_CERT};
use lazy_static::lazy_static;
use serde_json::Value;
use std::{
    env,
    string::{String, ToString},
    thread,
    time::Duration,
    vec::Vec,
};
use test_utils::*;

lazy_static! {
    static ref SERVER_ADDRESS: String = {
        let host = env::var("HOSTNAME").expect("failed to get env 'HOSTNAME'");
        format!("{}:12345", host)
    };
}
const LISTEN_ADDRESS: &str = "0.0.0.0:12345";

pub fn run_tests() -> bool {
    check_all_passed!(run_tests!(test_request_response,),)
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
    set_env_vars();
    let spid = env::var("SPID").unwrap();
    let ias_url = env::var("IAS_URL").unwrap();
    let sub_key = env::var("SUB_KEY").unwrap();

    let attested_tls_config =
        AttestedTlsConfig::new_by_ra(&spid, &ias_url, &sub_key, IAS_ROOT_CERT.to_vec()).unwrap();

    start_server(attested_tls_config.clone(), IAS_ROOT_CERT.to_vec());
    let client_config = ClientConfig::from_attested_tls_config(attested_tls_config)
        .unwrap()
        .set_attestation_report_verifier(IAS_ROOT_CERT.to_vec(), *ENCLAVE_MEASUREMENT);
    let mut client = Client::new(&*SERVER_ADDRESS, &client_config).unwrap();
    let msg = r#"{
        "message": "Hello test_request_response"
    }"#;
    let resp: String = client.send_json(msg).unwrap();

    assert_eq!(msg, resp);
}

fn start_server(attested_tls_config: AttestedTlsConfig, ias_root_cert: Vec<u8>) {
    let server_config = ServerConfig::from_attested_tls_config(attested_tls_config)
        .unwrap()
        .set_attestation_report_verifier(ias_root_cert, *ENCLAVE_MEASUREMENT);

    let mut server = Server::new(LISTEN_ADDRESS.to_string(), server_config);
    let handler = EchoHandler::default();
    thread::spawn(move || server.run(handler).unwrap());
    thread::sleep(Duration::from_secs(1));
}
