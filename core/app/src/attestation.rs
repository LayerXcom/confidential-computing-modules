// Defined in https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf

use serde_json::Value;
use reqwest::Client;
use std::{
    io::Read,
    convert::TryFrom,
};
use crate::error::*;

// Attestation Verification Report
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AVReport {
    id: String,
    timestamp: String,
    version: usize,
    #[serde(rename = "isvEnclaveQuoteStatus")]
    isv_enclave_quote_status: String,
    #[serde(rename = "isvEnclaveQuoteBody")]
    isv_enclave_quote_body: String,
    #[serde(rename = "revocationReason")]
    revocation_reason: Option<String>,
    #[serde(rename = "pseManifestStatus")]
    pse_manifest_status: Option<String>,
    #[serde(rename = "pseManifestHash")]
    pse_manifest_hash: Option<String>,
    #[serde(rename = "platformInfoBlob")]
    platform_info_blob: Option<String>,
    nonce: Option<String>,
    #[serde(rename = "epidPseudonym")]
    epid_pseudonym: Option<String>,
}

pub struct Quote {
    quote_body: QuoteBody,
    report_body: ReportBody,
}

impl TryFrom<&[u8]> for Quote {
    type Error = HostError;

    fn try_from(from: &[u8]) -> Result<Self> {
        let quote_body = QuoteBody::read(&from[..48])?;
        let report_body = ReportBody::read(&from[48..432])?;

        Ok(Quote {
            quote_body,
            report_body,
        })
    }
}

// Size: 48 bytes
#[derive(Clone, Copy, Default, PartialEq)]
pub struct QuoteBody {
    version: [u8; 2],
    sig_type: [u8; 2],
    gid: [u8; 4],
    isv_svn_qe: [u8; 2],
    isv_svn_pce: [u8; 2],
    reserved: [u8; 4],
    base_name: [u8; 32],
}

impl QuoteBody {
    pub fn read<R: Read>(mut reader: R) -> Result<Self> {
        let mut quote_body: QuoteBody = Default::default();

        reader.read_exact(&mut quote_body.version)?;
        reader.read_exact(&mut quote_body.sig_type)?;
        reader.read_exact(&mut quote_body.gid)?;
        reader.read_exact(&mut quote_body.isv_svn_qe)?;
        reader.read_exact(&mut quote_body.isv_svn_pce)?;
        reader.read_exact(&mut quote_body.reserved)?;
        reader.read_exact(&mut quote_body.base_name)?;

        if reader.read(&mut [0u8])? != 0 {
            return Err(HostErrorKind::Quote("String passed to QuoteBody is too big.").into());
        }

        Ok(quote_body)
    }
}

// Size: 384 bytes
#[derive(Clone, Copy)]
pub struct ReportBody {
    spu_svn: [u8; 16],
    misc_select: [u8; 4],
    reserved1: [u8; 28],
    attributes: [u8; 16],
    mr_enclave: [u8; 32],
    reserved2: [u8; 32],
    mr_signer: [u8; 32],
    reserved3: [u8; 96],
    isv_prod_id: [u8; 2],
    isv_svn: [u8; 2],
    reserved4: [u8; 60],
    report_data: [u8; 64],
}

impl Default for ReportBody {
    fn default() -> Self {
        ReportBody {
            spu_svn: [0u8; 16],
            misc_select: [0u8; 4],
            reserved1: [0u8; 28],
            attributes: [0u8; 16],
            mr_enclave: [0u8; 32],
            reserved2: [0u8; 32],
            mr_signer: [0u8; 32],
            reserved3: [0u8; 96],
            isv_prod_id: [0u8; 2],
            isv_svn: [0u8; 2],
            reserved4: [0u8; 60],
            report_data: [0u8; 64],
        }
    }
}

impl ReportBody {
    pub fn read<R: Read>(mut reader: R) -> Result<Self> {
        let mut report_body: ReportBody = Default::default();

        reader.read_exact(&mut report_body.spu_svn)?;
        reader.read_exact(&mut report_body.misc_select)?;
        reader.read_exact(&mut report_body.reserved1)?;
        reader.read_exact(&mut report_body.attributes)?;
        reader.read_exact(&mut report_body.mr_enclave)?;
        reader.read_exact(&mut report_body.reserved2)?;
        reader.read_exact(&mut report_body.mr_signer)?;
        reader.read_exact(&mut report_body.reserved3)?;
        reader.read_exact(&mut report_body.isv_prod_id)?;
        reader.read_exact(&mut report_body.isv_svn)?;
        reader.read_exact(&mut report_body.reserved4)?;
        reader.read_exact(&mut report_body.report_data)?;

        if reader.read(&mut [0u8])? != 0 {
            return Err(HostErrorKind::Quote("String passed to ReportBody is too big.").into());
        }

        Ok(report_body)
    }
}

pub struct AttestationService {
    url: String,
    retries: u32,
}

impl AttestationService {
    pub fn new(url: String, retries: u32) -> Self {
        AttestationService {
            url,
            retries,
        }
    }

    // todo: use enum instead of boolean
    pub fn get_report(&self, quote: &str, is_prod: bool) -> Result<ASResponse> {
        let req = Self::build_req(quote, is_prod);
        self.send_req(&req)
    }

    fn build_req(quote: &str, is_prod: bool) -> QuoteRequest {
        QuoteRequest {
            jsonrpc: "2.0".to_string(),
            method: "validate".to_string(),
            params: Params {
                quote: quote.to_string(),
                production: is_prod,
            },
            id: 1,
        }
    }

    fn send_req(&self, req: &QuoteRequest) -> Result<ASResponse> {
        let client = reqwest::Client::new();
        self.try_send_req(&client, req).or_else(|mut res_err| {
            for _ in 0..self.retries {
                self.try_send_req(&client, req).map_err(|e| res_err = e);
            }
            return Err(res_err);
        })
    }

    fn try_send_req(&self, client: &Client, req: &QuoteRequest) -> Result<ASResponse> {
        let mut res = client.post(self.url.as_str()).json(&req).send()?;
        let res_str = res.text()?;
        let json_res: Value = serde_json::from_str(res_str.as_str())?;

        if res.status().is_success() && !json_res["error"].is_object() {
            let res = self.parse_response(&json_res);
            Ok(res)
        } else {
            let msg = format!(
                "AttestationSevice: An error occurred. Status code: {:?}\n Error response: {:?}",
                res.status(),
                json_res["error"]["message"].as_str()
            );
            Err(HostErrorKind::AS(msg).into())
        }
    }

    // todo: unwrap()
    fn parse_response(&self, v: &Value) -> ASResponse {
        let result = self.parse_result(v);
        let id = v["id"].as_i64().unwrap();
        let jsonrpc = v["jsonrpc"].as_str().unwrap().to_string();

        ASResponse {
            id,
            jsonrpc,
            result,
        }
    }

    // todo: unwrap()
    fn parse_result(&self, v: &Value) -> ASResult {
        let ca = v["result"]["ca"].as_str().unwrap().to_string();
        let certificate = v["result"]["certificate"].as_str().unwrap().to_string();
        let sig = v["result"]["signature"].as_str().unwrap().to_string();
        let report_string = v["result"]["report"].as_str().unwrap().to_string();
        let validate = match v["result"]["validate"].as_str() {
            Some(v) => v == "True",
            None => false,
        };
        let report = self.parse_report(v);

        ASResult {
            ca,
            certificate,
            sig,
            validate,
            report,
            report_string
        }
    }

    // todo: unwrap()
    fn parse_report(&self, v: &Value) -> AVReport {
        let report_str = v["result"]["report"].as_str().unwrap();
        serde_json::from_str(report_str).unwrap()
    }
}

// JSON-RPC response from an attestation service. This includes a validated report.
#[derive(Serialize, Deserialize, Debug)]
pub struct ASResponse {
    id: i64,
    jsonrpc: String,
    result: ASResult,
}

// A result of `ASResponse`.
#[derive(Serialize, Deserialize, Debug)]
pub struct ASResult {
    pub ca: String,
    pub certificate: String,
    pub report: AVReport,
    pub report_string: String,
    pub sig: String,
    pub validate: bool,
}

// Parameter of `QuoteRequst`.
#[derive(Serialize, Deserialize, Debug)]
pub struct Params {
    pub quote: String,
    pub production: bool,
}

// JSON-RPC request to send quote to an attestation service.
#[derive(Serialize, Deserialize, Debug)]
pub struct QuoteRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Params,
    pub id: i32,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::*;

    #[test]
    fn test_get_report() {
        let ias = AttestationService::new(IAS_URL.to_string(), IAS_DEFAULT_RETRIES);
        let quote = "AgAAANoKAAAHAAYAAAAAALAzX9O8HMqPgE65imQgWS3bL6zst0H4QfxKAKurXXnVBAX/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAIzp3AzhlP03bwcSpF+o5J3dlTq2zu0T03uf7PbnLtMYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9sUtS1/Vn5lvk3Mxh+eX0AOjdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAADM2OO98uEjJQLRmzAvAqO4nirzimAHK0PjdgI8MT0xKDy/Paohf208N04YWgzl4kOjrG0X/T8LUphwzn3qB7XkycWqDO9RsLbNIpKRiVBIttztbn0/kxcwo6p54OeOLfhFbxaTn0wkzEYJhGWVR+j6IUGxubDwinf0fO+2vPu20kW1NzSV/Le8fyYzC4v5sIblVW8VZESsbuFd+bFbbcNzco9cH6cNI68FMkeMHoZF/Z4HvP7DR2sIiLnmYcavDbTlzG7OwaTDNcTCNfKsKReK76TRtu+m018QArsRTdrAwx7gZY2788RBpn0veSkU+v9QxNnZmqfpMolAXdu3ksQul4R8bzQ8HoiRkQvedCY8K+5j3GLvDjLCUgB4JP8Vhtt6KjABRO5o4+s3Uj2gBAABJIOqpxIvbG5zmizV7zUe4jAJQoPVM3jtcxXwU9PH5saXiCPHBpTEBpK/2r/5bUnIIBkshRbQ8/kP6/lLhEOu3Fkfh7UMMoizPO8uGQimLBGwbAFyAgU4G8TGeUbYWEGuRRJoKDoclzm9edJZ7mApMlmiT9t2VMLMsg7l49sO1T1TtgK/zpwwLvr2f4a/vmkJWviOcIRimFD+V20xw+EMXYl8Aj4x4Rw62+oiQe0mKvh3K4gXIamejnQHZ/Mrbeh8ai0n1J+GMeKFxxSkeytGZVrT+a75WjLAcJtt5QAU3Em1ELsWLUVUI58mLTe/u+hsjTlWizXAruElzhCIijvR96aHc+lzd/a+EmsQ4mI/mWPxqdoUciznhG4VlxNAhXSw8zn77k8m+1GaBSxvAUDwFOf/V3KcQUYp5Cswo1MD4t26Rn5LBqF1I0I27d/BHD+KUwl7W5doG4Ec6egnoofkSTUnjI3G+9btxIVV2nYWzfXauZzseiZQn";
        let res = ias.get_report(quote, false).unwrap();
    }
}
