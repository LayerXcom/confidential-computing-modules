use crate::bincode;
use crate::crypto_box::KEY_SIZE;
use crate::local_anyhow::{anyhow, Result};
use crate::localstd::{boxed::Box, fmt, vec::Vec};
use crate::serde::{
    de::{self, SeqAccess, Unexpected},
    ser::SerializeTuple,
    Deserialize, Serialize, Serializer,
};
use crate::SodiumPrivateKey;
use frame_common::crypto::SEALED_DATA_SIZE;
use sgx_tseal::SgxSealedData;
use sgx_types::sgx_sealed_data_t;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnsealedEnclaveDecryptionKey([u8; KEY_SIZE]);

impl UnsealedEnclaveDecryptionKey {
    pub fn from_sodium_priv_key(priv_key: &SodiumPrivateKey) -> Self {
        let buf = bincode::serialize(&priv_key).unwrap(); // must not fail
        let mut res = [0u8; KEY_SIZE];
        res.copy_from_slice(&buf[..]);
        Self(res)
    }

    pub fn encoded_sealing(self) -> Result<Vec<u8>> {
        let additional = [0u8; 0];
        let sealed_data = SgxSealedData::<Self>::seal_data(&additional, &self)
            .map_err(|e| anyhow!("error: {:?}", e))?;

        Ok(SealedEnclaveDecryptionKey::new(sealed_data).encode())
    }
}

unsafe impl sgx_types::marker::ContiguousMemory for UnsealedEnclaveDecryptionKey {}

#[derive(Default, Clone)]
pub struct SealedEnclaveDecryptionKey<'a>(SgxSealedData<'a, UnsealedEnclaveDecryptionKey>);

impl<'a> SealedEnclaveDecryptionKey<'a> {
    pub fn new(sealed_data: SgxSealedData<'a, UnsealedEnclaveDecryptionKey>) -> Self {
        Self(sealed_data)
    }

    pub fn unsealing(&self) -> Result<UnsealedEnclaveDecryptionKey> {
        let unsealed_data = self
            .0
            .unseal_data()
            .map_err(|e| anyhow!("error: {:?}", e))?;

        Ok(*unsealed_data.get_decrypt_txt())
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() // must not fail
    }

    pub fn decode(
        bytes: &'a [u8],
    ) -> crate::localstd::result::Result<Self, Box<bincode::ErrorKind>> {
        bincode::deserialize(bytes)
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
        for byte in bytes.iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

impl<'de> Deserialize<'de> for SealedEnclaveDecryptionKey<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct SealedEnclaveDecryptionKeyVisitor;

        impl<'de> de::Visitor<'de> for SealedEnclaveDecryptionKeyVisitor {
            type Value = SealedEnclaveDecryptionKey<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a SealedEnclaveDecryptionKey must be 32 bytes length")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut_v = &mut value.to_vec()[..];
                let sealed_data = unsafe {
                    SgxSealedData::<UnsealedEnclaveDecryptionKey>::from_raw_sealed_data_t(
                        mut_v.as_mut_ptr() as *mut sgx_sealed_data_t,
                        SEALED_DATA_SIZE as u32,
                    )
                }
                .ok_or_else(|| {
                    E::custom(&"Fail SgxSealedData::<UnsealedEnclaveDecryptionKey>::from_raw_sealed_data_t")
                })?;

                Ok(SealedEnclaveDecryptionKey::new(sealed_data))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = [0u8; SEALED_DATA_SIZE];
                for i in 0..SEALED_DATA_SIZE {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or(de::Error::invalid_length(i, &"32"))?;
                }

                let sealed_data = unsafe {
                    SgxSealedData::<UnsealedEnclaveDecryptionKey>::from_raw_sealed_data_t(
                        bytes.as_mut_ptr() as *mut sgx_sealed_data_t,
                        SEALED_DATA_SIZE as u32,
                    )
                }
                .ok_or_else(|| {
                    de::Error::invalid_value(
                        Unexpected::Bytes(&bytes[..]),
                        &"Fail SgxSealedData::<UnsealedEnclaveDecryptionKey>::from_raw_sealed_data_t",
                    )
                })?;

                Ok(SealedEnclaveDecryptionKey::new(sealed_data))
            }
        }

        deserializer.deserialize_tuple(SEALED_DATA_SIZE, SealedEnclaveDecryptionKeyVisitor)
    }
}

impl fmt::Debug for SealedEnclaveDecryptionKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedEnclaveDecryptionKey").finish()
    }
}
