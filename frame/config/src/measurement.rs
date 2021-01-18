use crate::localstd::{string::String, vec::Vec};

#[cfg(feature = "sgx")]
#[derive(Debug, Clone, Copy)]
pub struct EnclaveMeasurement {
    mr_signer: [u8; 32],
    mr_enclave: [u8; 32],
}

#[cfg(feature = "sgx")]
impl EnclaveMeasurement {
    pub fn new_from_dumpfile(content: String) -> Self {
        let lines: Vec<&str> = content.split("\n").collect();
        let mr_signer_index = lines
            .iter()
            .position(|&line| line == "mrsigner->value:")
            .expect("mrsigner must be included");
        let mr_enclave_index = lines
            .iter()
            .position(|&line| line == "metadata->enclave_css.body.enclave_hash.m:")
            .expect("mrenclave must be included");

        let mr_signer = Self::parse_measurement(&lines[..], mr_signer_index);
        let mr_enclave = Self::parse_measurement(&lines[..], mr_enclave_index);

        Self {
            mr_signer,
            mr_enclave,
        }
    }

    fn parse_measurement(lines: &[&str], index: usize) -> [u8; 32] {
        let v: Vec<u8> = [lines[index + 1], lines[index + 2]]
            .concat()
            .split_whitespace()
            .map(|e| hex::decode(&e[2..]).unwrap()[0])
            .collect();

        let mut res = [0u8; 32];
        res.copy_from_slice(&v);
        res
    }

    pub fn mr_signer(&self) -> [u8; 32] {
        self.mr_signer
    }

    pub fn mr_enclave(&self) -> [u8; 32] {
        self.mr_enclave
    }
}
