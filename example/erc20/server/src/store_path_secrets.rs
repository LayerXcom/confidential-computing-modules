use std::fs;
use frame_common::crypto::ExportPathSecret;
use failure::Error;

pub struct StorePathSecret(ExportPathSecret);

impl StorePathSecret {
    pub fn new(eps: ExportPathSecret) -> Self {
        StorePathSecret(eps)
    }

    pub fn store_to_local_filesystem(self) -> Result<(), Error> {
        let uuid = uuid::Uuid::new_v4();
        
        unimplemented!();
    }
}

