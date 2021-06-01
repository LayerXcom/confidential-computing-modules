use crate::type_crypt::{Pad16BytesDecrypt, Pad16BytesEncrypt};
use module_encrypted_sql_ops_ecall_types::{
    enc_type::EncInteger, enclave_types::EnclavePlainInteger,
};
use std::{convert::TryInto, vec::Vec};

/// Plain representation of INTEGER.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct PlainI32(i32);

impl PlainI32 {
    /// Constructor
    pub fn new(i: i32) -> Self {
        Self(i)
    }

    /// Get raw representation
    pub fn to_i32(&self) -> i32 {
        self.0
    }
}

impl From<PlainI32> for Vec<u8> {
    fn from(p: PlainI32) -> Self {
        p.0.to_be_bytes().to_vec()
    }
}

impl From<Vec<u8>> for PlainI32 {
    fn from(v: Vec<u8>) -> Self {
        Self(i32::from_be_bytes(v.try_into().unwrap()))
    }
}

impl Pad16BytesEncrypt for PlainI32 {
    type Encrypted = EncInteger;
}

impl Pad16BytesDecrypt for EncInteger {
    type Decrypted = PlainI32;
    const DECRYPTED_SIZE: usize = 4;
}

impl From<EnclavePlainInteger> for PlainI32 {
    fn from(e: EnclavePlainInteger) -> Self {
        let i = e.to_i32();
        Self(i)
    }
}
