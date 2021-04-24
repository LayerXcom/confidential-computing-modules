use crate::{handlers::handle_health_check, Server as KeyVaultServer};
use actix_web::{http::StatusCode, test, web, App};
use anonify_eth_driver::utils::*;
use frame_common::crypto::Ed25519ChallengeResponse;
use frame_config::{ANONIFY_PARAMS_DIR, PJ_ROOT_DIR};
use frame_host::EnclaveDir;
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use once_cell::sync::Lazy;
use rand_core::{CryptoRng, RngCore};
use serde_json::json;
#[cfg(test)]
use std::str::FromStr;
use std::{env, fs, path::Path, sync::Arc};
use web3::{contract::Options, types::Address};

mod enclave_key;
mod treekem;

const SR_DEC_KEY_FILE_NAME: &'static str = "sr_enclave_decryption_key";
const KV_DEC_KEY_FILE_NAME: &'static str = "kv_enclave_decryption_key";

#[actix_rt::test]
async fn test_health_check() {
    set_env_vars();
    set_server_env_vars();

    let key_vault_server_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let key_vault_server_eid = key_vault_server_enclave.geteid();

    let server = KeyVaultServer::new(key_vault_server_eid);
    let unhealthy_server = Arc::new(server.clone());
    let mut unhealthy_app = test::init_service(
        App::new()
            .data(unhealthy_server.clone())
            .route("/api/v1/health", web::get().to(handle_health_check)),
    )
    .await;
    let req = test::TestRequest::get().uri("/api/v1/health").to_request();
    let resp = test::call_service(&mut unhealthy_app, req).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let healthy_server = Arc::new(server.run().await);
    let mut healthy_app = test::init_service(
        App::new()
            .data(healthy_server.clone())
            .route("/api/v1/health", web::get().to(handle_health_check)),
    )
    .await;
    let req = test::TestRequest::get().uri("/api/v1/health").to_request();
    let resp = test::call_service(&mut healthy_app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

pub static SUBSCRIBER_INIT: Lazy<()> = Lazy::new(|| {
    use test_utils::tracing::{GLOBAL_TRACING_BUF, TracingWriter};
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_core::Dispatch;

    let mock_writer = TracingWriter::new(&*GLOBAL_TRACING_BUF);

    let subscriber: Dispatch = tracing_subscriber::fmt()
        .with_writer(mock_writer)
        .with_max_level(tracing::Level::DEBUG)
        .with_level(true)
        .into();
    subscriber.init()
});

fn set_env_vars() {
    *SUBSCRIBER_INIT;
    env::set_var("RUST_LOG", "DEBUG");
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    env::set_var(
        "IAS_URL",
        "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report",
    );
    env::set_var("ENCLAVE_PKG_NAME", "key_vault");
    env::set_var("CMD_DEC_SECRET_DIR", ".anonify/test_pathsecrets");
}

fn set_env_vars_for_treekem() {
    env::set_var("ANONIFY_ABI_PATH", "contract-build/AnonifyWithTreeKem.abi");
    env::set_var("ANONIFY_BIN_PATH", "contract-build/AnonifyWithTreeKem.bin");
}

fn set_server_env_vars() {
    env::set_var("CONFIRMATIONS", "0");
    env::set_var("ACCOUNT_INDEX", "0");
    env::set_var("PASSWORD", "anonify0101");
}

fn clear_local_path_secrets() {
    let target_dir =
        PJ_ROOT_DIR.join(&env::var("CMD_DEC_SECRET_DIR").expect("CMD_DEC_SECRET_DIR is not set"));
    let dir = fs::read_dir(&target_dir).unwrap();

    for path in dir {
        if path.as_ref().unwrap().file_type().unwrap().is_dir() {
            continue;
        }
        let target = target_dir.join(path.unwrap().file_name());
        fs::remove_file(target).unwrap();
    }
}

fn clear_remote_path_secrets(roster_idx: String) {
    let target_dir = PJ_ROOT_DIR
        .join(&env::var("CMD_DEC_SECRET_DIR").expect("CMD_DEC_SECRET_DIR is not set"))
        .join(roster_idx);
    let dir = fs::read_dir(&target_dir).unwrap();

    for path in dir {
        if path.as_ref().unwrap().file_type().unwrap().is_dir() {
            continue;
        }
        let target = target_dir.join(path.unwrap().file_name());
        fs::remove_file(target).unwrap();
    }
}

fn clear_path_secrets() {
    let target =
        PJ_ROOT_DIR.join(&env::var("CMD_DEC_SECRET_DIR").expect("CMD_DEC_SECRET_DIR is not set"));
    if target.exists() {
        fs::remove_dir_all(target).unwrap();
    }
}

fn clear_local_dec_key_file() {
    let target = ANONIFY_PARAMS_DIR.join(SR_DEC_KEY_FILE_NAME);
    if target.exists() {
        fs::remove_file(target).unwrap();
    }
}

fn clear_remote_dec_key_file() {
    let target = ANONIFY_PARAMS_DIR.join(KV_DEC_KEY_FILE_NAME);
    if target.exists() {
        fs::remove_file(target).unwrap();
    }
}

fn clear_dec_key_files() {
    clear_local_dec_key_file();
    clear_remote_dec_key_file();
}

fn get_local_id() -> Option<String> {
    let paths = fs::read_dir(
        PJ_ROOT_DIR.join(&env::var("CMD_DEC_SECRET_DIR").expect("CMD_DEC_SECRET_DIR is not set")),
    )
    .unwrap();
    for path in paths {
        if path.as_ref().unwrap().file_type().unwrap().is_dir() {
            continue;
        }
        return Some(path.unwrap().file_name().into_string().unwrap());
    }

    None
}

fn get_local_ids() -> Vec<String> {
    let mut ids = vec![];
    let paths = fs::read_dir(
        PJ_ROOT_DIR.join(&env::var("CMD_DEC_SECRET_DIR").expect("CMD_DEC_SECRET_DIR is not set")),
    )
    .unwrap();
    for path in paths {
        if path.as_ref().unwrap().file_type().unwrap().is_dir() {
            continue;
        }
        ids.push(path.unwrap().file_name().into_string().unwrap());
    }

    ids
}

fn get_remote_ids(roster_idx: String) -> Vec<String> {
    let mut ids = vec![];
    let paths = fs::read_dir(
        PJ_ROOT_DIR
            .join(&env::var("CMD_DEC_SECRET_DIR").expect("CMD_DEC_SECRET_DIR is not set"))
            .join(roster_idx),
    )
    .unwrap();
    for path in paths {
        if path.as_ref().unwrap().file_type().unwrap().is_dir() {
            continue;
        }
        ids.push(path.unwrap().file_name().into_string().unwrap());
    }

    ids
}

async fn verify_enclave_encryption_key<P: AsRef<Path> + Copy>(
    enclave_encryption_key: SodiumPubKey,
    factory_abi_path: P,
    anonify_abi_path: P,
    eth_url: &str,
) -> SodiumPubKey {
    let factory_contract_address = Address::from_str(
        &env::var("FACTORY_CONTRACT_ADDRESS").expect("FACTORY_CONTRACT_ADDRESS is not set"),
    )
    .unwrap();

    let anonify_contract_address: Address =
        create_contract_interface(eth_url, factory_abi_path, factory_contract_address)
            .unwrap()
            .query("getAnonifyAddress", (), None, Options::default(), None)
            .await
            .unwrap();

    let query_enclave_encryption_key: Vec<u8> =
        create_contract_interface(eth_url, anonify_abi_path, anonify_contract_address)
            .unwrap()
            .query(
                "getEncryptionKey",
                enclave_encryption_key.to_bytes(),
                None,
                Options::default(),
                None,
            )
            .await
            .unwrap();

    assert_eq!(
        enclave_encryption_key,
        SodiumPubKey::from_bytes(&query_enclave_encryption_key).unwrap()
    );

    enclave_encryption_key
}

fn init_100_req<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
    counter: u32,
) -> state_runtime_node_api::state::post::Request
where
    CR: RngCore + CryptoRng,
{
    let sig = [
        236, 103, 17, 252, 166, 199, 9, 46, 200, 107, 188, 0, 37, 111, 83, 105, 175, 81, 231, 14,
        81, 100, 221, 89, 102, 172, 30, 96, 15, 128, 117, 146, 181, 221, 149, 206, 163, 208, 113,
        198, 241, 16, 150, 248, 99, 170, 85, 122, 165, 197, 14, 120, 110, 37, 69, 32, 36, 218, 100,
        64, 224, 226, 99, 2,
    ];
    let pubkey = [
        164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33, 189,
        55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
    ];
    let challenge = [
        244, 158, 183, 202, 237, 236, 27, 67, 39, 95, 178, 136, 235, 162, 188, 106, 52, 56, 6, 245,
        3, 101, 33, 155, 58, 175, 168, 63, 73, 125, 205, 225,
    ];
    let access_policy = Ed25519ChallengeResponse::new_from_bytes(sig, pubkey, challenge);

    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "total_supply": 100,
        },
        "cmd_name": "construct",
        "counter": counter,
    });

    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, &serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request {
        ciphertext,
        user_id: None,
    }
}

fn balance_of_req<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
) -> state_runtime_node_api::state::get::Request
where
    CR: RngCore + CryptoRng,
{
    let sig = [
        21, 54, 136, 84, 150, 59, 196, 71, 164, 136, 222, 128, 100, 84, 208, 219, 84, 7, 61, 11,
        230, 220, 25, 138, 67, 247, 95, 97, 30, 76, 120, 160, 73, 48, 110, 43, 94, 79, 192, 195,
        82, 199, 73, 80, 48, 148, 233, 143, 87, 237, 159, 97, 252, 226, 68, 160, 137, 127, 195,
        116, 128, 181, 47, 2,
    ];
    let pubkey = [
        164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33, 189,
        55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
    ];
    let challenge = [
        119, 177, 182, 220, 100, 44, 96, 179, 173, 47, 220, 49, 105, 204, 132, 230, 211, 24, 166,
        219, 82, 76, 27, 205, 211, 232, 142, 98, 66, 130, 150, 202,
    ];
    let access_policy = Ed25519ChallengeResponse::new_from_bytes(sig, pubkey, challenge);
    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, &serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::get::Request { ciphertext }
}
