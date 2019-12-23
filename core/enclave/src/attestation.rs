use std::{
    prelude::v1::*,
    net::TcpStream,
};
use https_enclave::{HttpsClient, parse_response_attn_report};
use crate::{
    error::Result,
    bridges::ocalls::get_ias_socket,
    cert::verify_report_cert,
};

pub const DEV_HOSTNAME : &str = "api.trustedservices.intel.com";
pub const REPORT_PATH : &str = "/sgx/dev/attestation/v3/report";
pub const IAS_DEFAULT_RETRIES: u32 = 10;
pub const TEST_SPID: &str = "2C149BFC94A61D306A96211AED155BE9";
pub const TEST_SUB_KEY: &str = "77e2533de0624df28dc3be3a5b9e50d9";

pub struct AttestationService<'a> {
    host: &'a str,
    path: &'a str,
    retries: u32,
}

impl<'a> AttestationService<'a> {
    pub fn new(host: &'a str, path: &'a str, retries: u32) -> Self {
        AttestationService {
            host,
            path,
            retries,
        }
    }

    pub fn get_report_and_sig(&self, quote: &str, ias_api_key: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let req = self.raw_report_req(quote, ias_api_key);
        let (report, sig) = self.send_raw_req(req)?;
        // let (report, sig) = verify_report_cert(payload.as_bytes())?;
        Ok((report.as_bytes().to_vec(), sig.as_bytes().to_vec()))
    }

    fn raw_report_req(&self, quote: &str, ias_api_key: &str) -> String {
        let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", quote);
        format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
            &self.path,
            &self.host,
            ias_api_key,
            encoded_json.len(),
            encoded_json
        )
    }

    fn send_raw_req(&self, req: String) -> Result<(String, String)> {
        let fd = get_ias_socket()?;
        let mut socket = TcpStream::new(fd)?;

        // TODO: Fix to call `HttpsClient` to use non-blocking communications.
        let res = https_enclave::get_report_response(&mut socket, req)?;
        // let mut client = HttpsClient::new(socket, &self.host)?;
        // let res = client.send_from_raw_req(&req)?;

        let (report, sig, sig_cert) = parse_response_attn_report(&res);
        // let payload = report + "|" + &sig + "|" + &sig_cert;
        Ok((report, sig))
    }

}

