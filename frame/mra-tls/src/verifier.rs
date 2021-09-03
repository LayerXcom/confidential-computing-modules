use crate::cert::*;
use crate::error::{MraTLSError, Result};
use anyhow::anyhow;
use frame_config::EnclaveMeasurement;
use log::debug;
use remote_attestation::AttestedReport;
use std::io::{Cursor, Read};
use std::vec::Vec;

#[derive(Clone, Debug)]
pub struct AttestedReportVerifier {
    root_cert: Vec<u8>,
    measurement: EnclaveMeasurement,
}

impl AttestedReportVerifier {
    pub fn new(root_cert: Vec<u8>, measurement: EnclaveMeasurement) -> Self {
        Self {
            root_cert,
            measurement,
        }
    }

    fn verify_cert(&self, ee_cert: &[u8]) -> Result<()> {
        // Parse DER formatted x.509 end entity certificate
        let x509 = yasna::parse_der(&ee_cert, X509::load)?;
        // Extract tbs (To Be Signed) Certificate
        let tbs_cert: <TbsCert as Asn1Ty>::ValueTy = x509.0;
        let pubkey: <PubKey as Asn1Ty>::ValueTy = ((((((tbs_cert.1).1).1).1).1).1).0;
        let cert_ext: <SgxRaCertExt as Asn1Ty>::ValueTy = (((((((tbs_cert.1).1).1).1).1).1).1).0;
        let cert_ext_payload: Vec<u8> = ((cert_ext.0).1).0;

        // Verify the deserialized attested_report which is included in extension field of X.509 cert
        let attested_report = serde_json::from_slice::<AttestedReport>(&cert_ext_payload)?
            .verify_attested_report(self.root_cert.to_vec())?;

        let mut quote = Cursor::new(attested_report.get_quote_body()?);
        let mut mr_enclave = [0u8; 32];
        let mut mr_signer = [0u8; 32];
        let mut report_data = [0u8; 64];

        // Offsets are defined in "Attestation Service for Intel® Software Guard Extensions (Intel® SGX): API Documentation version 6.0"
        quote.set_position(112);
        quote.read_exact(&mut mr_enclave)?;
        quote.set_position(176);
        quote.read_exact(&mut mr_signer)?;
        quote.set_position(368);
        quote.read_exact(&mut report_data)?;

        Self::verify_pubkey_eq(pubkey, report_data)?;

        #[cfg(feature = "verify-mr-enclave-enable")]
        self.verify_mr_enclave(mr_enclave)?;

        self.verify_mr_signer(mr_signer)?;

        Ok(())
    }

    fn verify_pubkey_eq(pubkey: <PubKey as Asn1Ty>::ValueTy, report_data: [u8; 64]) -> Result<()> {
        let raw_pubkey = (pubkey.1).0.to_bytes();
        let is_uncompressed = raw_pubkey[0] == 4;
        if !is_uncompressed || raw_pubkey[1..] != report_data[..] {
            return Err(MraTLSError::Error(anyhow!(
                "ee_cert's pubkey is not equal to report data"
            )));
        }

        Ok(())
    }

    #[cfg(feature = "verify-mr-enclave-enable")]
    fn verify_mr_enclave(&self, mr_enclave: [u8; 32]) -> Result<()> {
        println!("##### verify_mr_enclave");
        if self.measurement.mr_enclave() != mr_enclave {
            return Err(MraTLSError::Error(anyhow!(
                "Invalid mr_enclave: local mr_enclave: {:?}, received mr_enclave: {:?}",
                self.measurement.mr_enclave(),
                mr_enclave
            )));
        }

        Ok(())
    }

    fn verify_mr_signer(&self, mr_signer: [u8; 32]) -> Result<()> {
        if self.measurement.mr_signer() != mr_signer {
            return Err(MraTLSError::Error(anyhow!(
                "Invalid mr_signer: local mr_signer: {:?}, received mr_signer: {:?}",
                self.measurement.mr_signer(),
                mr_signer
            )));
        }

        Ok(())
    }
}

impl rustls::ClientCertVerifier for AttestedReportVerifier {
    fn client_auth_root_subjects(
        &self,
        _sni: Option<&webpki::DNSName>,
    ) -> Option<rustls::DistinguishedNames> {
        Some(rustls::DistinguishedNames::new())
    }

    fn verify_client_cert(
        &self,
        certs: &[rustls::Certificate],
        _sni: Option<&webpki::DNSName>,
    ) -> std::result::Result<rustls::ClientCertVerified, rustls::TLSError> {
        debug!("Start verifying the certificate of mutual attested tls in client side...");
        if certs.len() != 1 {
            return Err(rustls::TLSError::NoCertificatesPresented);
        }

        match self.verify_cert(&certs[0].0) {
            Ok(_) => Ok(rustls::ClientCertVerified::assertion()),
            Err(err) => Err(rustls::TLSError::General(format!(
                "WebPKI ExtensionValueInvalid Error: {:?}",
                err
            ))),
        }
    }
}

impl rustls::ServerCertVerifier for AttestedReportVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef,
        _ocsp: &[u8],
    ) -> std::result::Result<rustls::ServerCertVerified, rustls::TLSError> {
        debug!("Start verifying the certificate of mutual attested tls in server side...");
        if certs.len() != 1 {
            return Err(rustls::TLSError::NoCertificatesPresented);
        }
        match self.verify_cert(&certs[0].0) {
            Ok(_) => Ok(rustls::ServerCertVerified::assertion()),
            Err(err) => Err(rustls::TLSError::General(format!(
                "WebPKI ExtensionValueInvalid Error: {:?}",
                err
            ))),
        }
    }
}
