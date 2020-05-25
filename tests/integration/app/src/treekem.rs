use anonify_test_utils::test_case;
use anonify_treekem::{EciesCiphertext, DhPubKey, DhPrivateKey};

#[test_case]
pub fn ecies_correctness() {
    let plaintext = b"ecies correctness test";
    let priv_key = DhPrivateKey::from_random().unwrap();
    let pub_key = DhPubKey::from_private_key(&priv_key);

    let ciphertext = EciesCiphertext::encrypt(&pub_key, plaintext.to_vec()).unwrap();
    let recovered_plaintext = ciphertext.decrypt(&priv_key).unwrap();

    assert_eq!(recovered_plaintext, plaintext);
}
