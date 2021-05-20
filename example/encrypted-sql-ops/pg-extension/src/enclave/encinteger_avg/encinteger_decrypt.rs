use std::convert::TryInto;

use aes::{cipher::generic_array::GenericArray, Aes128, BlockDecrypt, NewBlockCipher};

use crate::host::encinteger_avg::{DecryptError, EncInteger};

use super::MASTER_KEY;

pub(in crate::enclave) trait EncIntegerDecrypt {
    fn decrypt(self) -> Result<i32, DecryptError>;
}

impl EncIntegerDecrypt for EncInteger {
    fn decrypt(self) -> Result<i32, DecryptError> {
        let encrypted = self.as_slice();

        let key = GenericArray::from_slice(&MASTER_KEY);
        let mut enc_block = GenericArray::clone_from_slice(&encrypted);

        let cipher = Aes128::new(&key);

        let dec_block = {
            cipher.decrypt_block(&mut enc_block);
            enc_block
        };
        let decrypted = dec_block.to_vec();
        let decrypted: [u8; 16] = decrypted.try_into().map_err(|orig_vec: Vec<u8>| {
            DecryptError::new(format!(
                "decrypted block is {} bytes, while expected to be 16 bytes (4-byte integer with 16-byte padding))",
                orig_vec.len()
            ))
        })?;

        Ok(i32::from_be_bytes(
            decrypted[..4].try_into().expect("length already checked"),
        ))
    }
}
