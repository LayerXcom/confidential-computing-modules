use crate::IAS_REPORT_CA;
use anyhow::{anyhow, bail, ensure, Result};
use http_req::{
    request::{Method, Request},
    response::{Headers, Response},
    uri::Uri,
};
use log::debug;
use serde_json::Value;
use std::{
    io::{BufReader, Write},
    prelude::v1::*,
    str,
    time::SystemTime,
};

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

/// The very high level service for remote attestations
pub struct RAService;

impl RAService {
    pub fn remote_attestation(
        uri: &str,
        ias_api_key: &str,
        quote: &str,
    ) -> Result<(AttestationReport, ReportSig)> {
        let uri: Uri = uri.parse().expect("Invalid uri");
        let body = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", quote);
        let mut writer = Vec::new();

        let response = RAClient::new(&uri)
            .ias_apikey_header_mut(ias_api_key)
            .quote_body_mut(&body.as_bytes())
            .send(&mut writer)?;

        let ra_resp = RAResponse::from_response(writer, response)?.verify_attestation_report()?;

        Ok((ra_resp.attestation_report, ra_resp.report_sig))
    }
}

/// A client for remote attestation with IAS
pub struct RAClient<'a> {
    request: Request<'a>,
    host: String,
}

impl<'a> RAClient<'a> {
    pub fn new(uri: &'a Uri) -> Self {
        let host = uri.host_header().expect("Not found host in the uri");

        RAClient {
            request: Request::new(&uri),
            host,
        }
    }

    /// Sets IAS API KEY to header.
    pub fn ias_apikey_header_mut(&mut self, ias_api_key: &str) -> &mut Self {
        let mut headers = Headers::new();
        headers.insert("HOST", &self.host);
        headers.insert("Ocp-Apim-Subscription-Key", ias_api_key);
        headers.insert("Connection", "close");
        self.request.headers(headers);
        self.request.method(Method::POST);

        self
    }

    /// Sets the body to the JSON serialization of the passed value, and
    /// also sets the `Content-Type: application/json` header.
    pub fn quote_body_mut(&'a mut self, body: &'a [u8]) -> &mut Self {
        let len = body.len().to_string();
        self.request.header("Content-Type", "application/json");
        self.request.header("Content-Length", &len);
        self.request.body(&body);

        self
    }

    pub fn send<T: Write>(&self, writer: &mut T) -> Result<Response> {
        self.request
            .send(writer)
            .map_err(|e| anyhow!("{:?}", e))
            .map_err(Into::into)
    }
}

/// A response from IAS
#[derive(Debug, Clone)]
pub struct RAResponse {
    attestation_report: AttestationReport,
    report_sig: ReportSig,
    cert: Vec<u8>,
}

impl RAResponse {
    pub fn from_response(body: Vec<u8>, resp: Response) -> Result<Self> {
        debug!("RA response: {:?}", resp);

        let headers = resp.headers();
        let sig = headers
            .get("X-IASReport-Signature")
            .ok_or_else(|| anyhow!("Not found X-IASReport-Signature header"))?;
        let report_sig = ReportSig::base64_decode(sig.as_bytes())?;

        let cert = headers
            .get("X-IASReport-Signing-Certificate")
            .ok_or_else(|| anyhow!("Not found X-IASReport-Signing-Certificate"))?
            .replace("%0A", "");
        let cert = percent_decode(cert)?;

        Ok(RAResponse {
            attestation_report: AttestationReport::new(body),
            report_sig,
            cert,
        })
    }

    /// Verify that
    /// 1. TLS server certificate
    /// 2. report's signature
    /// 3. report's timestamp
    /// 4. quote status
    fn verify_attestation_report(self) -> Result<Self> {
        let now_func = webpki::Time::try_from(SystemTime::now())?;

        let mut ca_reader = BufReader::new(IAS_REPORT_CA.as_bytes());
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add_pem_file(&mut ca_reader)
            .expect("Failed to add CA");

        let trust_anchors: Vec<webpki::TrustAnchor> = root_store
            .roots
            .iter()
            .map(|cert| cert.to_trust_anchor())
            .collect();

        let ias_cert_dec = Self::decode_ias_report_ca()?;
        let mut chain: Vec<&[u8]> = Vec::new();
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
            &self.attestation_report.as_bytes(),
            &self.report_sig.as_bytes(),
        )?;

        let attn_report = self.attestation_report.as_json()?;
        self.verify_timestamp(&attn_report)?;
        self.verify_quote_status(&attn_report)?;

        Ok(self)
    }

    /// Verify report's timestamp is within 24H (90day is recommended by Intel)
    fn verify_timestamp(&self, attn_report: &Value) -> Result<()> {
        if let Value::String(_time) = &attn_report["timestamp"] {
            Ok(())
        // TODO
        // let time_fixed = time.clone() + "+0000";
        // let ts = DateTime::parse_from_str(&time_fixed, "%Y-%m-%dT%H:%M:%S%.f%z").unwrap().timestamp();
        // let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        // ensure!(now - ts > 0, "")
        } else {
            bail!("Failed to fetch timestamp from attestation report");
        }
    }

    /// Verify the quote status included the attestation report is OK
    fn verify_quote_status(&self, attn_report: &Value) -> Result<()> {
        if let Value::String(quote_status) = &attn_report["isvEnclaveQuoteStatus"] {
            match quote_status.as_ref() {
                "OK" => Ok(()),
                "GROUP_OUT_OF_DATE" => {
                    println!("Enclave Quote Status: GROUP_OUT_OF_DATE");
                    Ok(())
                }
                _ => bail!("Invalid Enclave Quote Status: {}", quote_status),
            }
        } else {
            bail!("Failed to fetch isvEnclaveQuoteStatus from attestation report");
        }
    }

    fn decode_ias_report_ca() -> Result<Vec<u8>> {
        let mut ias_ca_stripped = IAS_REPORT_CA.as_bytes().to_vec();
        ias_ca_stripped.retain(|&x| x != 0x0d && x != 0x0a);
        let head_len = "-----BEGIN CERTIFICATE-----".len();
        let tail_len = "-----END CERTIFICATE-----".len();

        let full_len = ias_ca_stripped.len();
        let ias_ca_core: &[u8] = &ias_ca_stripped[head_len..full_len - tail_len];
        let ias_cert_dec = base64::decode(ias_ca_core)?;
        Ok(ias_cert_dec)
    }
}

/// A report returned from IAS
#[derive(Debug, Clone, Default)]
pub struct AttestationReport(Vec<u8>);

impl AttestationReport {
    pub fn new(report: Vec<u8>) -> Self {
        AttestationReport(report)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn as_json(&self) -> Result<Value> {
        serde_json::from_slice(&self.as_bytes()).map_err(Into::into)
    }
}

/// Signature of the attestation report
#[derive(Debug, Clone, Default)]
pub struct ReportSig(Vec<u8>);

impl ReportSig {
    pub fn base64_decode(v: &[u8]) -> Result<Self> {
        let v = base64::decode(v)?;
        Ok(ReportSig(v))
    }

    pub fn new(report_sig: Vec<u8>) -> Self {
        ReportSig(report_sig)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

fn percent_decode(orig: String) -> Result<Vec<u8>> {
    let v: Vec<&str> = orig.split('%').collect();
    ensure!(!v.is_empty(), "Certificate is blank");
    let mut ret = String::new();
    ret.push_str(v[0]);
    if v.len() > 1 {
        for s in v[1..].iter() {
            ret.push(u8::from_str_radix(&s[0..2], 16)? as char);
            ret.push_str(&s[2..]);
        }
    }
    let v: Vec<&str> = ret.split("-----").collect();
    base64::decode(v[2]).map_err(Into::into)
}
