// Defined in https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf

use serde_json::Value;
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
