use crate::application::AppKeyChain;
use crate::group_state::GroupState;
use crate::handshake::{Handshake, PathSecretKVS, PathSecretSource};
use crate::local_anyhow::anyhow;
use crate::local_rand;
use crate::local_rand_core::SeedableRng;
use anonify_config::{IAS_URL, KEY_VAULT_ENDPOINT, SPID, SUB_KEY};

pub fn init_path_secret_kvs(kvs: &mut PathSecretKVS, until_roster_idx: usize, until_epoch: usize) {
    let mut csprng = local_rand::rngs::StdRng::seed_from_u64(1);
    for r_i in 0..until_roster_idx {
        for e_i in 0..until_epoch {
            kvs.insert_random_path_secret(r_i as u32, e_i as u32, &mut csprng);
        }
    }
}

pub fn do_handshake_three_party(
    my_group: &mut GroupState,
    others_group1: &mut GroupState,
    others_group2: &mut GroupState,
    source: &PathSecretSource,
) -> (AppKeyChain, AppKeyChain, AppKeyChain) {
    let max_roster_idx = 2;
    let (handshake, _) = my_group.create_handshake(source).unwrap();

    let my_keychain = my_group
        .process_handshake(
            &handshake,
            source,
            max_roster_idx,
            &*SPID,
            IAS_URL,
            &*SUB_KEY,
            KEY_VAULT_ENDPOINT,
        )
        .unwrap();
    let others_keychain1 = others_group1
        .process_handshake(
            &handshake,
            source,
            max_roster_idx,
            &*SPID,
            IAS_URL,
            &*SUB_KEY,
            KEY_VAULT_ENDPOINT,
        )
        .unwrap();
    let others_keychain2 = others_group2
        .process_handshake(
            &handshake,
            source,
            max_roster_idx,
            &*SPID,
            IAS_URL,
            &*SUB_KEY,
            KEY_VAULT_ENDPOINT,
        )
        .unwrap();

    (my_keychain, others_keychain1, others_keychain2)
}

pub fn encrypt_decrypt_helper(
    msg: &[u8],
    group1: &GroupState,
    app_key_chain1: &mut AppKeyChain,
    group2: &GroupState,
    app_key_chain2: &mut AppKeyChain,
    group3: &GroupState,
    app_key_chain3: &mut AppKeyChain,
) {
    let app_msg = app_key_chain1.encrypt_msg(msg.to_vec(), group1).unwrap();

    match app_key_chain1.decrypt_msg(&app_msg, group1).unwrap() {
        Some(plaintext1) => match app_key_chain2.decrypt_msg(&app_msg, group2).unwrap() {
            Some(plaintext2) => match app_key_chain3.decrypt_msg(&app_msg, group3).unwrap() {
                Some(plaintext3) => {
                    assert_eq!(plaintext1, plaintext2);
                    assert_eq!(plaintext2, plaintext3);
                    assert_eq!(plaintext3.as_slice(), msg);
                }
                None => {}
            },
            None => {}
        },
        None => {}
    };
}
