use anyhow::{Result, anyhow};

pub mod dh;
pub mod ecies;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod secrets;

pub const SHA256_OUTPUT_LEN: usize = 256 / 8;

pub trait CryptoRng: rand::RngCore + rand::CryptoRng {}
impl<T> CryptoRng for T
    where T: rand::RngCore + rand::CryptoRng {}

/// Generating a random number inside the enclave.
pub fn sgx_rand_assign(rand: &mut [u8]) -> Result<()> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)
        .map_err(|e| anyhow!("error rsgx_read_rand: {:?}", e))
}
