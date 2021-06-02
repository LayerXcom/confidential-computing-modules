use crate::type_crypt::{Pad16BytesDecrypt, Pad16BytesEncrypt};
use module_encrypted_sql_ops_ecall_types::{
    enc_type::EncInteger, enclave_types::EnclavePlainInteger,
};
use std::{convert::TryInto, vec::Vec};

/// Plain representation of INTEGER.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct PlainInteger(i32);

impl PlainInteger {
    /// Constructor
    pub fn new(i: i32) -> Self {
        Self(i)
    }

    /// Get raw representation
    pub fn to_i32(&self) -> i32 {
        self.0
    }
}

impl From<PlainInteger> for Vec<u8> {
    fn from(p: PlainInteger) -> Self {
        p.0.to_be_bytes().to_vec()
    }
}

impl From<Vec<u8>> for PlainInteger {
    fn from(v: Vec<u8>) -> Self {
        Self(i32::from_be_bytes(v.try_into().unwrap()))
    }
}

impl Pad16BytesEncrypt for PlainInteger {
    type Encrypted = EncInteger;
}

impl Pad16BytesDecrypt for EncInteger {
    type Decrypted = PlainInteger;
    const DECRYPTED_SIZE: usize = 4;
}

impl From<EnclavePlainInteger> for PlainInteger {
    fn from(e: EnclavePlainInteger) -> Self {
        let i = e.to_i32();
        Self(i)
    }
}
