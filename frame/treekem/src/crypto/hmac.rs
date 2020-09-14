use std::vec::Vec;
use super::{CryptoRng, SHA256_OUTPUT_LEN};
use ring::{
    hmac::{SigningKey, SigningContext, HMAC_SHA256},
};
use codec::Encode;

#[derive(Debug, Clone, Encode, Default, Copy, PartialEq)]
pub struct HmacKey([u8; SHA256_OUTPUT_LEN]);

impl HmacKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

     pub fn new_from_random<R: CryptoRng>(csprng: &mut R) -> HmacKey {
        let mut buf = [0u8; SHA256_OUTPUT_LEN];
        csprng.fill_bytes(&mut buf);
        HmacKey(buf)
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::new(HMAC_SHA256, &self.0);
        let mut ctx = SigningContext::with_key(&signing_key);
        ctx.update(&msg);
        ctx.sign().as_ref().to_vec()
    }
}

impl From<[u8; SHA256_OUTPUT_LEN]> for HmacKey {
    fn from(array: [u8; SHA256_OUTPUT_LEN]) -> Self {
        HmacKey(array)
    }
}

impl From<Vec<u8>> for HmacKey {
    fn from(vec: Vec<u8>) -> Self {
        assert_eq!(vec.len(), SHA256_OUTPUT_LEN);
        let mut res = [0u8; SHA256_OUTPUT_LEN];
        &res.copy_from_slice(&vec);
        HmacKey(res)
    }
}

impl From<&[u8]> for HmacKey {
    fn from(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), SHA256_OUTPUT_LEN);
        let mut res = [0u8; SHA256_OUTPUT_LEN];
        &res.copy_from_slice(&bytes);
        HmacKey(res)
    }
}
