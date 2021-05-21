use crate::application::AppKeyChain;
use crate::group_state::GroupState;
use crate::handshake::{Handshake, PathSecretKVS, PathSecretSource};
use crate::{PathSecret, StorePathSecrets};
use anyhow::anyhow;
use frame_config::CMD_DEC_SECRET_DIR;
use rand_core::SeedableRng;
use std::env;

pub fn init_path_secret_kvs(kvs: &mut PathSecretKVS, until_roster_idx: usize, until_epoch: usize) {
    let mut csprng = rand::rngs::StdRng::seed_from_u64(1);
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
    let max_roster_idx = env::var("MAX_ROSTER_IDX")
        .expect("MAX_ROSTER_IDX is not set")
        .parse::<u32>()
        .unwrap();
    let (handshake, _) = my_group.create_handshake(source).unwrap();
    let store_path_secrets = StorePathSecrets::new(&*CMD_DEC_SECRET_DIR);

    let my_keychain = my_group
        .process_handshake(
            &store_path_secrets,
            &handshake,
            source,
            max_roster_idx,
            #[cfg(feature = "backup-enable")]
                recover_path_secret_from_key_vault_for_test,
        )
        .unwrap();
    let others_keychain1 = others_group1
        .process_handshake(
            &store_path_secrets,
            &handshake,
            source,
            max_roster_idx,
            #[cfg(feature = "backup-enable")]
                recover_path_secret_from_key_vault_for_test,
        )
        .unwrap();
    let others_keychain2 = others_group2
        .process_handshake(
            &store_path_secrets,
            &handshake,
            source,
            max_roster_idx,
            #[cfg(feature = "backup-enable")]
                recover_path_secret_from_key_vault_for_test,
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

fn recover_path_secret_from_key_vault_for_test(
    id: &[u8],
    roster_idx: u32,
) -> anyhow::Result<PathSecret> {
    use frame_config::{IAS_ROOT_CERT, KEY_VAULT_ENCLAVE_MEASUREMENT};
    use frame_mra_tls::{
        key_vault::{
            request::{KeyVaultCmd, KeyVaultRequest, RecoverPathSecretRequestBody},
            response::RecoveredPathSecret,
        },
        AttestedTlsConfig, Client, ClientConfig,
    };

    let recover_request_body = RecoverPathSecretRequestBody::new(roster_idx, id.to_vec());
    let ias_url = env::var("IAS_URL").expect("IAS_URL is not set");
    let key_vault_endpoint = env::var("KEY_VAULT_ENDPOINT_FOR_STATE_RUNTIME")
        .expect("KEY_VAULT_ENDPOINT_FOR_STATE_RUNTIME is not set");
    let spid = env::var("SPID").expect("SPID is not set");
    assert!(!spid.is_empty(), "SPID shouldn't be empty");
    let sub_key = env::var("SUB_KEY").expect("SUB_KEY is not set");
    assert!(!sub_key.is_empty(), "SUB_KEY shouldn't be empty");

    let attested_tls_config =
        AttestedTlsConfig::new_by_ra(&spid, &ias_url, &sub_key, IAS_ROOT_CERT.to_vec())?;

    let client_config = ClientConfig::from_attested_tls_config(attested_tls_config)?
        .set_attestation_report_verifier(IAS_ROOT_CERT.to_vec(), *KEY_VAULT_ENCLAVE_MEASUREMENT);
    let mut mra_tls_client = Client::new(&key_vault_endpoint, &client_config)?;
    let backup_request = KeyVaultRequest::new(KeyVaultCmd::RecoverPathSecret, recover_request_body);
    let recovered_path_secret: RecoveredPathSecret = mra_tls_client.send_json(backup_request)?;
    Ok(PathSecret::from(recovered_path_secret.path_secret()))
}
