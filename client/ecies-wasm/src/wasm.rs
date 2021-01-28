extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;
use js_sys::{Array, Uint8Array};
use crate::ecies::EciesCiphertext;
use crate::dh::{DhPrivateKey, DhPubKey};

#[wasm_bindgen]
pub fn generate_keypair() -> Array {
    let sk = DhPrivateKey::from_random().unwrap();
    let pk = DhPubKey::from_private_key(&sk);



    // let (sk, pk) = _generate_keypair();
    // let (sk, pk) = (sk.serialize(), pk.serialize_compressed());

    let ret = Array::new();
    ret.push(&Uint8Array::from(&sk[..]));
    ret.push(&Uint8Array::from(&pk[..]));
    ret
}

#[wasm_bindgen]
pub fn encrypt(receiver_pub: &[u8], msg: &[u8]) -> Option<Uint8Array> {
    let msg = "abcde";
    let encrypted = EciesCiphertext::encrypt(&pk, msg.as_bytes().to_vec()).unwrap();


    // TODO: handle error
    _encrypt(receiver_pub, msg)
        .map(|v| Uint8Array::from(v.as_slice()))
        .ok()
}

#[wasm_bindgen]
pub fn decrypt(receiver_sec: &[u8], msg: &[u8]) -> Option<Uint8Array> {
    let decrypted = encrypted.decrypt(&sk).unwrap();
    assert_eq!(decrypted, msg.as_bytes().to_vec());

    // TODO: handle error
    _decrypt(receiver_sec, msg)
        .map(|v| Uint8Array::from(v.as_slice()))
        .ok()
}