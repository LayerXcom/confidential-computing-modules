use crate::Server as KeyVaultServer;
use actix_web::{test, web, App};
use frame_config::{ANONIFY_ABI_PATH, ANONIFY_PARAMS_DIR, FACTORY_ABI_PATH};
use frame_host::EnclaveDir;
use state_runtime_node_server::{handlers::*, Server as ERC20Server};
use std::{env, sync::Arc, time};
#[cfg(test)]
use test_utils::tracing::logs_contain;

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
    let _enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*FACTORY_ABI_PATH,
        &*ANONIFY_ABI_PATH,
        &eth_url,
    )
    .await;

    assert!((&*ANONIFY_PARAMS_DIR)
        .to_path_buf()
        .join(SR_DEC_KEY_FILE_NAME)
        .exists());
    assert!((&*ANONIFY_PARAMS_DIR)
        .to_path_buf()
        .join(KV_DEC_KEY_FILE_NAME)
        .exists());
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_enclave_key_manually_backup() {
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

    let erc20_server = ERC20Server::new(app_eid).await.run().await;
    let erc20_server = Arc::new(erc20_server);
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            )
            .route("/api/v1/backup", web::post().to(handle_backup)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let _enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*FACTORY_ABI_PATH,
        &*ANONIFY_ABI_PATH,
        &eth_url,
    )
    .await;

    clear_remote_dec_key_file();

    // ensure clearing remote enclave_key
    assert!(!(&*ANONIFY_PARAMS_DIR)
        .to_path_buf()
        .join(KV_DEC_KEY_FILE_NAME)
        .exists());

    // backup enclave_key to key-vault server
    let req = test::TestRequest::post().uri("/api/v1/backup").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    // check recovering enclave_key from remote
    assert!((&*ANONIFY_PARAMS_DIR)
        .to_path_buf()
        .join(KV_DEC_KEY_FILE_NAME)
        .exists());

    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_enclave_key_manually_recover() {
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

    let erc20_server = ERC20Server::new(app_eid).await.run().await;
    let erc20_server = Arc::new(erc20_server);
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            )
            .route("/api/v1/backup", web::post().to(handle_backup)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let _enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*FACTORY_ABI_PATH,
        &*ANONIFY_ABI_PATH,
        &eth_url,
    )
    .await;

    clear_local_dec_key_file();
    // ensure clearing remote path_secrets
    assert!(!(&*ANONIFY_PARAMS_DIR)
        .to_path_buf()
        .join(SR_DEC_KEY_FILE_NAME)
        .exists());

    // recover enclave_key from key-vault server
    let req = test::TestRequest::post()
        .uri("/api/v1/recover")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    // check recovering local enclave_key
    assert!((&*ANONIFY_PARAMS_DIR)
        .to_path_buf()
        .join(SR_DEC_KEY_FILE_NAME)
        .exists());

    assert!(!logs_contain("ERROR"));
}
