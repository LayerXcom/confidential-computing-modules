use std::vec::Vec;
use anonify_enclave_rpc::EnclaveHandler;
use crate::crypto::SYMMETRIC_KEY;
use anyhow::Result;

pub struct ShareSymmKey {

}

impl EnclaveHandler for ShareSymmKey {
    fn handle_req(&self, req: &[u8]) -> Result<Vec<u8>> {
        unimplemented!();
    }
}
