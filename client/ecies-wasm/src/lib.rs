pub mod dh;
pub mod ecies;
pub mod hkdf;
pub mod hmac;

pub const SHA256_OUTPUT_LEN: usize = 256 / 8;

pub trait CryptoRng: rand::RngCore + rand::CryptoRng {}
impl<T> CryptoRng for T where T: rand::RngCore + rand::CryptoRng {}

#[cfg(test)]
mod tests {
    use super::dh::{DhPrivateKey, DhPubKey};
    use super::ecies::EciesCiphertext;

    #[test]
    fn test_ecies() {
        let sk = DhPrivateKey::from_random().unwrap();
        let pk = DhPubKey::from_private_key(&sk);

        let msg = "abcde";
        let encrypted = EciesCiphertext::encrypt(&pk, msg.as_bytes().to_vec()).unwrap();

        let decrypted = encrypted.decrypt(&sk).unwrap();
        assert_eq!(decrypted, msg.as_bytes().to_vec());
    }
}
