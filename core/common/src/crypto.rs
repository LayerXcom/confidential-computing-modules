use crate::localstd::{
    io::{self, Read, Write},
    vec::Vec,
    string::String,
    convert::TryFrom,
};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, SignatureError, SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use crate::traits::*;
use frame_common::crypto::AccessRight;

pub const COMMON_SECRET: [u8; SECRET_KEY_LENGTH] = [182, 93, 72, 157, 114, 225, 213, 95, 237, 176, 179, 23, 11, 100, 177, 16, 129, 8, 41, 4, 158, 209, 227, 21, 89, 47, 118, 0, 232, 162, 217, 203];
pub const COMMON_CHALLENGE: [u8; CHALLENGE_SIZE] = [39, 79, 228, 49, 240, 219, 135, 53, 169, 47, 65, 111, 236, 125, 2, 195, 214, 154, 18, 77, 254, 135, 35, 77, 36, 45, 164, 254, 64, 8, 169, 238];

lazy_static! {
    pub static ref COMMON_ACCESS_RIGHT: AccessRight = {
        let secret = SecretKey::from_bytes(&COMMON_SECRET).unwrap();
        let pubkey = PublicKey::from(&secret);
        let keypair = Keypair { secret, public: pubkey };

        let sig = keypair.sign(&COMMON_CHALLENGE);

        assert!(keypair.verify(&COMMON_CHALLENGE, &sig).is_ok());
        AccessRight::new(sig, keypair.public, COMMON_CHALLENGE)
    };

    pub static ref OWNER_ADDRESS: UserAddress = {
        COMMON_ACCESS_RIGHT.user_address()
    };
}
