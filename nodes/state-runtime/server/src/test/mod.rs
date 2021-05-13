use crate::{handlers::*, Server};
use actix_web::{http::StatusCode, test, web, App};
use anonify_eth_driver::utils::*;
use frame_common::{
    crypto::{AccountId, NoAuth},
    AccessPolicy,
};
use frame_host::EnclaveDir;
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use integration_tests::set_env_vars;
use rand_core::{CryptoRng, RngCore};
use serde_json::json;
use std::{env, path::Path, str::FromStr, sync::Arc};
#[cfg(test)]
use test_utils::tracing::logs_contain;
use web3::{contract::Options, types::Address};

mod enclave_key;
mod treekem;

#[cfg(test)]
const SYNC_TIME: u64 = 1500;

#[actix_rt::test]
async fn test_health_check() {
    set_env_vars();

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();

    let server = Server::new(eid).await;
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
    assert!(!logs_contain("ERROR"));
}

fn my_turn() {
    env::remove_var("MY_ROSTER_IDX");
    env::remove_var("ACCOUNT_INDEX");
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("ACCOUNT_INDEX", "0");
}

#[allow(dead_code)]
fn other_turn() {
    env::remove_var("MY_ROSTER_IDX");
    env::remove_var("ACCOUNT_INDEX");
    env::set_var("MY_ROSTER_IDX", "1");
    env::set_var("ACCOUNT_INDEX", "1");
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

const INVALID_USER_ID: AccountId = AccountId([
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255,
]);

fn valid_user_id() -> NoAuth {
    NoAuth::new(AccountId::from_array([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    ]))
}

fn valid_other_user_id() -> NoAuth {
    NoAuth::new(AccountId::from_array([
        1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    ]))
}

// to me
fn init_100_req_fn<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
    counter: u32,
    user_id: Option<AccountId>,
) -> state_runtime_node_api::state::post::Request
where
    CR: RngCore + CryptoRng,
{
    let req = json!({
        "access_policy": valid_user_id(),
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
        user_id,
    }
}

// from me to other
fn transfer_10_req_fn<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
    counter: u32,
    user_id: Option<AccountId>,
) -> state_runtime_node_api::state::post::Request
where
    CR: RngCore + CryptoRng,
{
    let req = json!({
        "access_policy": valid_user_id(),
        "runtime_params": {
            "amount": 10,
            "recipient": valid_other_user_id().into_account_id(),
        },
        "cmd_name": "transfer",
        "counter": counter,
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, &serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request {
        ciphertext,
        user_id,
    }
}

// from other to me
fn transfer_other_5_req_fn<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
    counter: u32,
    user_id: Option<AccountId>,
) -> state_runtime_node_api::state::post::Request
where
    CR: RngCore + CryptoRng,
{
    let req = json!({
        "access_policy": valid_other_user_id(),
        "runtime_params": {
            "amount": 5,
            "recipient": valid_user_id().into_account_id(),
        },
        "cmd_name": "transfer",
        "counter": counter,
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, &serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request {
        ciphertext,
        user_id,
    }
}

// from me to other
fn transfer_110_req_fn<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
    counter: u32,
    user_id: Option<AccountId>,
) -> state_runtime_node_api::state::post::Request
where
    CR: RngCore + CryptoRng,
{
    let req = json!({
        "access_policy": valid_user_id(),
        "runtime_params": {
            "amount": 110,
            "recipient": valid_other_user_id().into_account_id(),
        },
        "cmd_name": "transfer",
        "counter": counter,
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, &serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request {
        ciphertext,
        user_id,
    }
}

fn balance_of_req_fn<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
) -> state_runtime_node_api::state::get::Request
where
    CR: RngCore + CryptoRng,
{
    let req = json!({
        "access_policy": valid_user_id(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, &serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::get::Request { ciphertext }
}

fn balance_of_other_req_fn<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
) -> state_runtime_node_api::state::get::Request
where
    CR: RngCore + CryptoRng,
{
    let req = json!({
        "access_policy": valid_other_user_id(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, &serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::get::Request { ciphertext }
}

fn user_counter_req_fn<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
) -> state_runtime_node_api::user_counter::get::Request
where
    CR: RngCore + CryptoRng,
{
    let req = json!({
        "access_policy": valid_user_id(),
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, &serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::user_counter::get::Request { ciphertext }
}
