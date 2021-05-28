//! Encryption / Decryption logic for EncInteger

use crate::{
    error::{EnclaveError, Result},
    plain_types::PlainAvgState,
};
use aes::{
    cipher::generic_array::GenericArray, Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher,
};
use module_encrypted_sql_ops_ecall_types::enc_type::EncInteger;
use std::{convert::TryInto, vec::Vec};

use super::MASTER_KEY;

pub(crate) trait EncAvgStateDecrypt {
    fn decrypt(self) -> Result<PlainAvgState>;
}

pub(crate) trait EncAvgStateEncrypt {
    fn encrypt(plain: PlainAvgState) -> Self;
}

impl EncAvgStateDecrypt for EnclaveEncAvgState {
    fn decrypt(self) -> Result<EnclavePlainAvgState> {
        let encrypted = self.as_slice();

        let key = GenericArray::from_slice(&MASTER_KEY);
        let mut enc_block = GenericArray::clone_from_slice(&encrypted);

        let cipher = Aes128::new(&key);

        let dec_block = {
            cipher.decrypt_block(&mut enc_block);
            enc_block
        };
        let decrypted = dec_block.to_vec();
        let decrypted: [u8; 16] =
            decrypted
                .try_into()
                .map_err(|orig_vec: Vec<u8>| EnclaveError::DecryptError {
                    decrypted_size: orig_vec.len(),
                    plain_size: 4,
                })?;

        Ok(i32::from_be_bytes(
            decrypted[..4].try_into().expect("length already checked"),
        ))
    }
}

impl EncAvgStateEncrypt for EncInteger {
    fn encrypt(integer: i32) -> Self {
        let key = GenericArray::from_slice(&MASTER_KEY);

        let mut plain_block = {
            let bytes4 = integer.to_be_bytes();
            let mut bytes16 = bytes4.to_vec();
            bytes16.extend_from_slice(&[0u8; 12]);
            GenericArray::clone_from_slice(&bytes16)
        };

        let cipher = Aes128::new(&key);

        let enc_block = {
            cipher.encrypt_block(&mut plain_block);
            plain_block
        };
        Self::from(enc_block.to_vec())
    }
}
