use crate::{handlers::handle_health_check, Server as KeyVaultServer};
use actix_web::{http::StatusCode, test, web, App};
use anonify_enclave::tests::DEC_KEY_FILE_NAME as SR_DEC_KEY_FILE_NAME;
use anonify_eth_driver::utils::*;
use frame_common::crypto::Ed25519ChallengeResponse;
use frame_config::{ANONIFY_ABI_PATH, ANONIFY_PARAMS_DIR, FACTORY_ABI_PATH, PJ_ROOT_DIR};
use frame_host::EnclaveDir;
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use key_vault_enclave::tests::DEC_KEY_FILE_NAME as KV_DEC_KEY_FILE_NAME;
use once_cell::sync::Lazy;
use rand_core::{CryptoRng, RngCore};
use serde_json::json;
use state_runtime_node_server::{handlers::*, Server as ERC20Server};
use std::{
    env, fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use web3::{contract::Options, types::Address};

use super::*;

#[actix_rt::test]
async fn test_enclave_key_backup() {
    set_env_vars();
    set_server_env_vars();
    clear_dec_key_files();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    // Setup key-vault server
    let key_vault_server_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize server enclave.");
    let key_vault_server_eid = key_vault_server_enclave.geteid();
    let key_vault_server = Arc::new(KeyVaultServer::new(key_vault_server_eid).run().await);
    let _key_vault_app = test::init_service(App::new().data(key_vault_server.clone())).await;
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Setup ERC20 application
    env::set_var("ENCLAVE_PKG_NAME", "erc20");
    let app_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize client enclave.");
    let app_eid = app_enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();

    let erc20_server = ERC20Server::new(app_eid).await.run().await;
    let erc20_server = Arc::new(erc20_server);
    let mut app = test::init_service(App::new().data(erc20_server.clone()).route(
        "/api/v1/enclave_encryption_key",
        web::get().to(handle_enclave_encryption_key),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*FACTORY_ABI_PATH,
        &*ANONIFY_ABI_PATH,
        &eth_url,
    )
    .await;

    assert!(&*ANONIFY_PARAMS_DIR
        .to_path_buf()
        .join(SR_DEC_KEY_FILE_NAME)
        .exists());
    assert!(&*ANONIFY_PARAMS_DIR
        .to_path_buf()
        .join(KV_DEC_KEY_FILE_NAME)
        .exists());
}
