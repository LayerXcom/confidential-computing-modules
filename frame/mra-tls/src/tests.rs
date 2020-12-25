use crate::{AttestedTlsConfig, Client, ClientConfig, RequestHandler, Server, ServerConfig};
use anonify_config::{ENCLAVE_MEASUREMENT, IAS_ROOT_CERT};
use anyhow::Result;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::{
    env,
    string::{String, ToString},
    thread,
    time::Duration,
    vec::Vec,
};
use test_utils::*;

static SERVER_ADDRESS: Lazy<String> = Lazy::new(|| {
    let host = env::var("HOSTNAME").expect("failed to get env 'HOSTNAME'");
    format!("{}:12345", host)
});
const LISTEN_ADDRESS: &str = "0.0.0.0:12345";

pub fn run_tests() -> bool {
    check_all_passed!(
        run_tests!(test_request_response, test_invalid_root_cert_failed,),
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
    set_env_vars();
    let spid = env::var("SPID").unwrap();
    let ias_url = env::var("IAS_URL").unwrap();
    let sub_key = env::var("SUB_KEY").unwrap();

    let attested_tls_config =
        AttestedTlsConfig::new_by_ra(&spid, &ias_url, &sub_key, IAS_ROOT_CERT.to_vec()).unwrap();

    start_server(attested_tls_config.clone());

    let client_config = ClientConfig::from_attested_tls_config(attested_tls_config)
        .unwrap()
        .set_attestation_report_verifier(IAS_ROOT_CERT.to_vec(), *ENCLAVE_MEASUREMENT);
    let mut client = Client::new(&*SERVER_ADDRESS, client_config).unwrap();

    let msg = r#"{
        "message": "Hello test_request_response"
    }"#;
    let resp: String = client.send_json(msg).unwrap();

    assert_eq!(msg, resp);
}

fn test_invalid_root_cert_failed() {
    
}

fn start_server(attested_tls_config: AttestedTlsConfig) {
    let server_config = ServerConfig::from_attested_tls_config(attested_tls_config)
        .unwrap()
        .set_attestation_report_verifier(IAS_ROOT_CERT.to_vec(), *ENCLAVE_MEASUREMENT);

    let mut server = Server::new(LISTEN_ADDRESS.to_string(), server_config);
    let handler = EchoHandler::default();
    thread::spawn(move || server.run(handler).unwrap());
    thread::sleep(Duration::from_secs(1));
}

const INVALID_ROOT_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIEAzCCAuugAwIBAgIJAJuGvZOz2wVdMA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNV
BAYTAkpQMQ4wDAYDVQQIDAVUb2t5bzEQMA4GA1UEBwwHQ2h1by1rdTEQMA4GA1UE
CgwHQW5vbmlmeTEUMBIGA1UECwwLQW5vbmlmeSBHci4xEzARBgNVBAMMCkFub25p
ZnkgQ0EwHhcNMjAxMjA4MDY0ODQ5WhcNMjExMjA4MDY0ODQ5WjBsMQswCQYDVQQG
EwJKUDEOMAwGA1UECAwFVG9reW8xEDAOBgNVBAcMB0NodW8ta3UxEDAOBgNVBAoM
B0Fub25pZnkxFDASBgNVBAsMC0Fub25pZnkgR3IuMRMwEQYDVQQDDApBbm9uaWZ5
IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvh7EGOiHi7iqgr0E
ybrs3s7k8W44z9DqmNreQbpGbQtN4DrpG550CaHco2P1bXRR3oMt7nVVYOzaSbsf
w9Y1Mvxk2GjEoAe2bQzTcfV8HIZvbPDB40yQlnlunk9EOP3Tn4h0wXvgxVt9uxHd
EpK5n1FDdictHXDD7oop7t+OjUgw5M1GMIfGsUrjFSKmvsDY7Wbj0vnYEh5Sb3BD
vH1lqIDQ1Aaxpo1Z3kq29oS8FdpGLHPAO+9MmDI2T+n5DzKV/EfLmLzNKHdXHmUH
QjUevxfbe/5GZne8ijEfiRpXpIpyvdTe4zXQqgUJ4It+qsWgTjV94zEZhPWKGsTK
bHfu2QIDAQABo4GnMIGkMIGGBgNVHSMEfzB9oXCkbjBsMQswCQYDVQQGEwJKUDEO
MAwGA1UECAwFVG9reW8xEDAOBgNVBAcMB0NodW8ta3UxEDAOBgNVBAoMB0Fub25p
ZnkxFDASBgNVBAsMC0Fub25pZnkgR3IuMRMwEQYDVQQDDApBbm9uaWZ5IENBggkA
m4a9k7PbBV0wDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCBPAwDQYJKoZIhvcNAQEL
BQADggEBACq+e+4uPQbdCLTAsDiDLXy9+GcAU2LIyhC2ONRy+dgdOPhr1gwvu5JK
yOg/5GNBqV1lOfxowo41un3bNsTjWMF6L0mVph2sZUe9wbMeNjkJLdEwTPeuevSG
h7Ke3XdZdAN9tya/RO0mxlhiHB7yPRW0cZmQ8mdh/vZei/MkIi8HWDYBKnBqTpHI
LF+otieQwv2+NiFY3iT9nyFsURG4ZF8Pz4jxN2mqUJvUZAyxIzCnFTLY+hdc04qE
+dEnJo9wuxKGH5gGOd9lIIkjxA3pNg5ve4Vngzc4a7BKK7qh1ZDwT2Ir4TEHublr
JdlBlga4mXz+WgmzNJZN8tujtyA5sh4=
-----END CERTIFICATE-----";
