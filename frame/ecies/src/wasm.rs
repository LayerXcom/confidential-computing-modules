extern crate wasm_bindgen;

use crate::dh::{DhPrivateKey, DhPubKey};
use crate::ecies::EciesCiphertext;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_keypair() -> Array {
    let sk = DhPrivateKey::from_random().unwrap();
    let pk = DhPubKey::from_private_key(&sk);

    let ret = Array::new();
    ret.push(&Uint8Array::from(&sk.serialize_bytes()[..]));
    ret.push(&Uint8Array::from(&pk.serialize_bytes()[..]));
    ret
}

#[wasm_bindgen]
pub fn encrypt(receiver_pub: &[u8], msg: &[u8]) -> Option<Uint8Array> {
    let pk = DhPubKey::from_bytes(receiver_pub).unwrap();
    let encrypted = EciesCiphertext::encrypt(&pk, msg.to_vec()).unwrap();

    Some(Uint8Array::from(&encrypted.serialize_bytes()[..]))
}

#[wasm_bindgen]
pub fn decrypt(receiver_sec: &[u8], encrypted: &[u8]) -> Option<Uint8Array> {
    let sk = DhPrivateKey::from_bytes(receiver_sec).unwrap();
    let encrypted = EciesCiphertext::from_bytes(encrypted).unwrap();
    let decrypted = encrypted.decrypt(&sk).unwrap();

    Some(Uint8Array::from(&decrypted[..]))
}
