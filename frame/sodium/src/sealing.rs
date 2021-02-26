use crate::bincode;
use crate::crypto_box::{self, aead::Aead, Box as CryptoBox, PublicKey, SecretKey, KEY_SIZE};
use crate::local_anyhow::{anyhow, Result};
use crate::localstd::{fmt, vec::Vec};
use crate::rand_core::{CryptoRng, RngCore};
use crate::serde::{
    de::{self, SeqAccess, Unexpected},
    ser::{self, SerializeTuple},
    Deserialize, Serialize, Serializer,
};
use crate::xsalsa20poly1305::{Nonce, NONCE_SIZE};

#[derive(Debug, Clone, Copy, PartialEq)]
struct UnsealedEnclaveDecryptionKey([u8; KEY_SIZE]);

impl UnsealedEnclaveDecryptionKey {
    pub fn from_sodium_priv_key(priv_key: SodiumPrivateKey) -> Self {
        let buf = bincode::serialize(&priv_key).unwrap(); // must not fail
        Self(buf)
    }

    pub fn sealing(self) -> Result<>  {
        let additional = [0u8; 0];
        let sealed_data = SgxSealedData::<Self>::seal_data(&additional, &self)
            .map_err(|e| anyhow!("error: {:?}", e))?;
    }
}

unsafe impl sgx_types::marker::ContiguousMemory for UnsealedEnclaveDecryptionKey {}

#[derive(Default, Clone)]
struct SealedEnclaveDecryptionKey<'a>(SgxSealedData<'a, UnsealedPathSecret>)

impl SealedEnclaveDecryptionKey {
    fn new(sealed_data: SgxSealedData<'a, UnsealedPathSecret>) -> Self {
        Self(sealed_data)
    }

    pub fn unsealing(&self) -> Result<UnsealedEnclaveDecryptionKey> {
        let unsealed_data = self
            .0
            .unseal_data()
            .map_err(|e| anyhow!("error: {:?}", e))?;

        Ok(*unsealed_data.get_decrypt_txt())
    }
}

impl Serialize for SealedEnclaveDecryptionKey<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![0u8; SEALED_DATA_SIZE];
        unsafe {
            self.0.to_raw_sealed_data_t(
                bytes.as_mut_ptr() as *mut sgx_sealed_data_t,
                SEALED_DATA_SIZE as u32,
            );
        }

        let mut tup = serializer.serialize_tuple(SEALED_DATA_SIZE)?;
        for byte in bytes {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}
