use crate::cert::*;
use crate::error::Result;
use std::vec::Vec;

#[derive(Clone, Debug)]
pub struct AttestedReportVerifier {
    root_cert: Vec<u8>,
    // ee_cert: Vec<u8>,
}

impl AttestedReportVerifier {
    pub fn new(root_cert: Vec<u8>) -> Self {
        Self { root_cert }
    }

    fn verify_cert(&self, ee_cert: &[u8]) -> Result<()> {
        // Parse DER formatted x.509 end entity certificate
        let x509 = yasna::parse_der(&ee_cert, X509::load)?;
        // Extract tbs (To Be Signed) Certificate
        let tbs_cert = <TbsCert as Asn1Ty>::ValueTy = x509.0;
        let pub_key: <PubKey as Asn1Ty>::ValueTy = ((((((tbs_cert.1).1).1).1).1).1).0;
        let pub_k = (pub_key.1).0;

        let cert_ext: <SgxRaCertExt as Asn1Ty>::ValueTy = (((((((tbs_cert.1).1).1).1).1).1).1).0;
        let cert_ext_payload: Vec<u8> = ((cert_ext.0).1).0;

        // Verify the deserialized attested_report which is included in extension field of X.509 cert
        let attested_report = serde_json::from_slice(&cert_ext_payload)?
            .verify_attested_report(&self.root_cert.to_vec())?;

        
        unimplemented!();
    }

    fn verify_measurements(&self) -> bool {
        // TODO
        true
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
        if certs.len() != 1 {
            return Err(rustls::TLSError::NoCertificatesPresented);
        }

        match self.verify_cert(&certs[0].0) {
            Ok(_) => Ok(rustls::ClientCertVerified::assertion()),
            Err(_) => Err(rustls::TLSError::WebPKIError(
                webpki::Error::ExtensionValueInvalid,
            )),
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
        if certs.len() != 1 {
            return Err(rustls::TLSError::NoCertificatesPresented);
        }
        match self.verify_cert(&certs[0].0) {
            Ok(_) => Ok(rustls::ServerCertVerified::assertion()),
            Err(_) => Err(rustls::TLSError::WebPKIError(
                webpki::Error::ExtensionValueInvalid,
            )),
        }
    }
}
