
use anonify_types::DB_VALUE_SIZE;
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::SgxSealedData;
use crate::error::Result;

#[derive(Copy, Clone)]
pub struct DbValue([u8; DB_VALUE_SIZE]);

unsafe impl ContiguousMemory for DbValue {}

#[derive(Copy, Clone)]
pub struct SealedDbValue([u8; DB_VALUE_SIZE]);

impl DbValue {
    pub fn seal(&self) -> Result<SealedDbValue> {
        let additional = [0u8; 0];
        let sealed_data = SgxSealedData::<DbValue>::seal_data(&additional, &self)?;
        let sealed_data_v = sealed_data.get_encrypt_txt();

        assert_eq!(sealed_data_v.len(), DB_VALUE_SIZE);
        let mut res = [0u8; DB_VALUE_SIZE];
        res.copy_from_slice(sealed_data_v);

        Ok(SealedDbValue(res))
    }
}

