use codec::{Decode, Encode, Input};
use std::vec::Vec;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateKey (rustls::PrivateKey);

impl Encode for PrivateKey {
    fn encode(&self) -> Vec<u8> {
        self.0.0.to_vec()
    }
}

impl Decode for PrivateKey {
    fn decode<I: Input>(value: &mut I) -> Result<Self, codec::Error> {
        let len = value.remaining_len()?
            .ok_or(codec::Error::from("PrivateKey length should not be zero"))?;
        let mut buf = vec![0u8; len];
        value.read(&mut buf)?;

        Ok(PrivateKey(rustls::PrivateKey(buf)))
    }
}

impl PrivateKey {
    pub fn as_rustls(&self) -> rustls::PrivateKey {
        self.0.clone()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Certificate(rustls::Certificate);

impl Encode for Certificate {
    fn encode(&self) -> Vec<u8> {
        self.0.0.to_vec()
    }
}

impl Decode for Certificate {
    fn decode<I: Input>(value: &mut I) -> Result<Self, codec::Error> {
        let len = value.remaining_len()?
            .ok_or(codec::Error::from("Certificate length should not be zero"))?;
        let mut buf = vec![0u8; len];
        value.read(&mut buf)?;

        Ok(Certificate(rustls::Certificate(buf)))
    }
}

impl Certificate {
    pub fn as_rustls(&self) -> rustls::Certificate {
        self.0.clone()
    }
}

pub mod pemfile {
    use std::{
        io,
        vec::Vec,
    };
    use super::{PrivateKey, Certificate};

    pub fn rsa_private_keys(rd: &mut dyn io::BufRead) -> Result<Vec<PrivateKey>, ()> {
        let rustls_private_keys = rustls::internal::pemfile::rsa_private_keys(rd)?;

        let private_keys: Vec<PrivateKey> = rustls_private_keys.iter()
            .map(|privkey| {PrivateKey(privkey.clone())}).collect();

        Ok(private_keys)
    }

    pub fn certs(rd: &mut dyn io::BufRead) -> Result<Vec<Certificate>, ()> {
        let rustls_certificates = rustls::internal::pemfile::certs(rd)?;

        let certificates: Vec<Certificate> = rustls_certificates.iter()
            .map(|cert| {Certificate(cert.clone())}).collect();

        Ok(certificates)
    }
}