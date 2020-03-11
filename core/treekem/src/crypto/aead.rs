use ring::aead::NonceSequence;

pub const AES_128_GCM_KEY_SIZE: usize = 128 / 8;
pub const AES_128_GCM_TAG_SIZE: usize = 128 / 8;
pub const AES_128_GCM_NONCE_SIZE: usize = 96 / 8;

pub struct Aes128GcmKey<N: NonceSequence> {
    opening_key: ring::aead::OpeningKey<N>,
    sealing_key: ring::aead::SealingKey<N>,
}

