use std::vec::Vec;

#[derive(Clone)]
pub struct AttestationReportVerifier {
    root_cert: Vec<u8>
}

impl AttestationReportVerifier {
    pub fn new(root_cert: Vec<u8>) -> Self {
        Self { root_cert }
    }

    fn verify_cert(&self, cert_der: &[u8]) -> bool {
        // TODO
        true
    }

    fn verify_measurements(&self) -> bool {
        // TODO
        true
    }
}

impl rustls::ClientCertVerifier for AttestationReportVerifier {
    fn client_auth_root_subjects(&self) -> rustls::DistinguishedNames {
        rustls::DistinguishedNames::new()
    }

    fn verify_client_cert(
        &self,
        certs: &[rustls::Certificate],
    ) -> std::result::Result<rustls::ClientCertVerified, rustls::TLSError> {
        if certs.len() != 1 {
            return Err(rustls::TLSError::NoCertificatesPresented);
        }

        if self.verify_cert(&certs[0].0) {
            Ok(rustls::ClientCertVerified::assertion())
        } else {
            Err(rustls::TLSError::WebPKIError(
                webpki::Error::ExtensionValueInvalid,
            ))
        }
    }
}

impl rustls::ServerCertVerifier for AttestationReportVerifier {
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
        if self.verify_cert(&certs[0].0) {
            Ok(rustls::ServerCertVerified::assertion())
        } else {
            Err(rustls::TLSError::WebPKIError(
                webpki::Error::ExtensionValueInvalid,
            ))
        }
    }
}
