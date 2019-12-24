use std::{
    prelude::v1::*,
    net::TcpStream,
    str,
    time::SystemTime,
    untrusted::time::SystemTimeEx,
    io::BufReader,
};
use https_enclave::HttpsClient;
use crate::{
    error::Result,
    ocalls::get_ias_socket,
    cert::verify_report_cert,
};

pub const DEV_HOSTNAME : &str = "api.trustedservices.intel.com";
pub const REPORT_PATH : &str = "/sgx/dev/attestation/v3/report";
pub const IAS_DEFAULT_RETRIES: u32 = 10;
pub const TEST_SPID: &str = "2C149BFC94A61D306A96211AED155BE9";
pub const TEST_SUB_KEY: &str = "77e2533de0624df28dc3be3a5b9e50d9";

pub const IAS_REPORT_CA: &[u8] = include_bytes!("../AttestationReportSigningCACert.pem");
type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

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
        let res = self.send_raw_req(req)?;

        res.verify_sig_cert()?;

        Ok((res.body, res.sig))
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

    fn send_raw_req(&self, req: String) -> Result<Response> {
        let fd = get_ias_socket()?;
        let mut socket = TcpStream::new(fd)?;

        // TODO: Fix to call `HttpsClient` to use non-blocking communications.
        let raw_res = https_enclave::get_report_response(&mut socket, req)?;
        // let mut client = HttpsClient::new(socket, &self.host)?;
        // let res = client.send_from_raw_req(&req)?;

        Response::parse(&raw_res)
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    sig: Vec<u8>,
    cert: Vec<u8>,
    body: Vec<u8>,
}

impl Response {
    pub fn parse(resp : &[u8]) -> Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut respp   = httparse::Response::new(&mut headers);
        let result = respp.parse(resp);

        let msg : &'static str;

        match respp.code {
            Some(200) => msg = "OK Operation Successful",
            Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
            Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
            Some(500) => msg = "Internal error occurred",
            Some(503) => msg = "Service is currently not able to process the request (due to
                a temporary overloading or maintenance). This is a
                temporary state – the same request can be repeated after
                some time. ",
            _ => {println!("DBG:{}", respp.code.unwrap()); msg = "Unknown error occured"},
        }

        println!("    [Enclave] msg = {}", msg);
        let mut len_num : u32 = 0;

        let mut sig = vec![];
        let mut cert_str = String::new();
        let mut body = vec![];

        for i in 0..respp.headers.len() {
            let h = respp.headers[i];
            match h.name{
                "Content-Length" => {
                    let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                    len_num = len_str.parse::<u32>().unwrap();
                }
                "X-IASReport-Signature" => sig = base64::decode(h.value)?,
                "X-IASReport-Signing-Certificate" => cert_str = String::from_utf8(h.value.to_vec()).unwrap(),
                _ => (),
            }
        }

        // Remove %0A from cert, and only obtain the signing cert
        cert_str = cert_str.replace("%0A", "");
        cert_str = percent_decode(cert_str);
        let v: Vec<&str> = cert_str.split("-----").collect();
        let cert = base64::decode(v[2])?;

        // This root_cert is equal to AttestationReportSigningCACert.pem
        // let root_cert = v[6].to_string();

        if len_num != 0 {
            let header_len = result.unwrap().unwrap();
            body = resp[header_len..].to_vec();
        }

        Ok(Response {
            sig,
            cert,
            body,
        })
    }

    fn verify_sig_cert(&self) -> Result<()> {
        let now_func = webpki::Time::try_from(SystemTime::now())?;

        let mut ca_reader = BufReader::new(&IAS_REPORT_CA[..]);
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_pem_file(&mut ca_reader).expect("Failed to add CA");

        let trust_anchors: Vec<webpki::TrustAnchor> = root_store
            .roots
            .iter()
            .map(|cert| cert.to_trust_anchor())
            .collect();

        let ias_cert_dec = Self::decode_ias_report_ca()?;
        let mut chain:Vec<&[u8]> = Vec::new();
        chain.push(&ias_cert_dec);

        let sig_cert = webpki::EndEntityCert::from(&self.cert)?;

        sig_cert.verify_is_valid_tls_server_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TLSServerTrustAnchors(&trust_anchors),
            &chain,
            now_func,
        )?;

        sig_cert.verify_signature(
            &webpki::RSA_PKCS1_2048_8192_SHA256,
            &self.body,
            &self.sig
        )?;

        Ok(())
    }

    // fn verify_report(&self) -> Result<()> {
    //     // timestamp is within 24H (90day is recommended by Intel)
    //     let attn_report: Value = serde_json::from_slice(attn_report_raw).unwrap();
    //     if let Value::String(time) = &attn_report["timestamp"] {
    //         let time_fixed = time.clone() + "+0000";
    //         let ts = DateTime::parse_from_str(&time_fixed, "%Y-%m-%dT%H:%M:%S%.f%z").unwrap().timestamp();
    //         let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    //     } else {
    //         println!("Failed to fetch timestamp from attestation report");
    //         return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    //     }
    // }

    fn decode_ias_report_ca() -> Result<Vec<u8>> {
        let mut ias_ca_stripped = IAS_REPORT_CA.to_vec();
        ias_ca_stripped.retain(|&x| x != 0x0d && x != 0x0a);
        let head_len = "-----BEGIN CERTIFICATE-----".len();
        let tail_len = "-----END CERTIFICATE-----".len();

        let full_len = ias_ca_stripped.len();
        let ias_ca_core : &[u8] = &ias_ca_stripped[head_len..full_len - tail_len];
        let ias_cert_dec = base64::decode(ias_ca_core)?;
        Ok(ias_cert_dec)
    }
}

fn percent_decode(orig: String) -> String {
    let v:Vec<&str> = orig.split('%').collect();
    let mut ret = String::new();
    ret.push_str(v[0]);
    if v.len() > 1 {
        for s in v[1..].iter() {
            ret.push(u8::from_str_radix(&s[0..2], 16).unwrap() as char);
            ret.push_str(&s[2..]);
        }
    }
    ret
}
