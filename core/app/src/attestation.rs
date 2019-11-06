// Defined in https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf

use serde_json;
use serde_json::Value;


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
    body: QuoteBody,
    report_body: ReportBody,
}



// Size: 48 bytes
pub struct QuoteBody {
    version: [u8; 2],
    sig_type: [u8; 2],
    gid: [u8; 4],
    isv_svn_qe: [u8; 2],
    isv_svn_pce: [u8; 2],
    reserved: [u8; 4],
    base_name: [u8; 32],
}

// impl QuoteBody {
//     pub fn read<R: Read>(mut reader: R) -> io
// }

// Size: 384 bytes
pub struct ReportBody {
    spu_svn: [u8; 16],
    misc_select: [u8; 4],
    reserved1: [u8; 28],
    attributes: [u8; 16],
    mrenclave: [u8; 32],
    reserved2: [u8; 32],
    mrsigner: [u8; 32],
    reserved3: [u8; 96],
    isv_prod_id: [u8; 2],
    isv_svn: [u8; 2],
    reserved4: [u8; 60],
    report_data: [u8; 64],
}
