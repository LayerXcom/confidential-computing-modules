use crate::error::{EnclaveError, Result};
use aes::{
    cipher::generic_array::GenericArray, Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher,
};
use std::{convert::TryInto, vec::Vec};

use super::MASTER_KEY;

pub(crate) trait Pad16BytesDecrypt
where
    Self: Sized + Into<Vec<u8>>,
{
    type Decrypted: From<Vec<u8>>;
    const DECRYPTED_SIZE: usize;

    fn decrypt(self) -> Result<Self::Decrypted> {
        let encrypted = self.into();

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
                    plain_size: Self::DECRYPTED_SIZE,
                })?;

        Ok(Self::Decrypted::from(
            decrypted[..Self::DECRYPTED_SIZE]
                .try_into()
                .expect("length already checked"),
        ))
    }
}

pub(crate) trait Pad16BytesEncrypt
where
    Self: Sized + Into<Vec<u8>>,
{
    type Encrypted: From<Vec<u8>>;

    fn encrypt(self) -> Self::Encrypted {
        let key = GenericArray::from_slice(&MASTER_KEY);

        let mut plain_block = {
            let mut bytes: Vec<u8> = self.into();
            bytes.resize(16, 0);
            GenericArray::clone_from_slice(&bytes)
        };

        let cipher = Aes128::new(&key);

        let enc_block = {
            cipher.encrypt_block(&mut plain_block);
            plain_block
        };
        Self::Encrypted::from(enc_block.to_vec())
    }
}
