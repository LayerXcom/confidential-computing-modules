use std::prelude::v1::*;
use https_enclave::{HttpsClient, parse_response_attn_report};
use crate::error::Result;

pub const DEV_HOSTNAME : &str = "api.trustedservices.intel.com";
pub const REPORT_SUFFIX : &str = "/sgx/dev/attestation/v3/report";
pub const IAS_DEFAULT_RETRIES: u32 = 10;
pub const DEFAULT_CERT_PATH: &str = "./dummy.pem";

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

    pub fn get_report(&self, quote: &str, ias_api_key: &str) -> Result<String> {
        let req = &self.raw_report_req(quote, ias_api_key);
        self.send_raw_req(&req)
    }

    fn raw_report_req(&self, quote: &str, ias_api_key: &str) -> String {
        let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", quote);
        format!(
            "POST {} HTTP/1.1\r\n
            HOST: {}\r\n
            Ocp-Apim-Subscription-Key:{}\r\n
            Content-Length:{}\r\n
            Content-Type: application/json\r\n
            Connection: close\r\n\r\n{}",
            &self.path,
            &self.host,
            ias_api_key,
            encoded_json.len(),
            encoded_json
        )
    }

    fn send_raw_req(&self, req: &str) -> Result<String> {
        let mut client = HttpsClient::new(&self.host, DEFAULT_CERT_PATH)?;
        let res = client.send_from_raw_req(req)?;
        let (report, sig, sig_cert) = parse_response_attn_report(&res);
        Ok(report)
    }

}
