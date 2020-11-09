pub mod dh;
pub mod ecies;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod secrets;

pub const SHA256_OUTPUT_LEN: usize = 256 / 8;

pub trait CryptoRng: crate::local_rand::RngCore + crate::local_rand::CryptoRng {}
impl<T> CryptoRng for T where T: crate::local_rand::RngCore + crate::local_rand::CryptoRng {}
