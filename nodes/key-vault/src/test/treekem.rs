use crate::Server as KeyVaultServer;
use actix_web::{test, web, App};
use frame_config::{ANONIFY_ABI_PATH, CMD_DEC_SECRET_DIR, FACTORY_ABI_PATH};
use frame_host::EnclaveDir;
use state_runtime_node_server::{handlers::*, Server as ERC20Server};
use std::{env, path::PathBuf, str::FromStr, sync::Arc, time};
#[cfg(test)]
use test_utils::tracing::logs_contain;

use super::*;

#[actix_rt::test]
async fn test_treekem_backup_path_secret() {
    set_env_vars();
    set_env_vars_for_treekem();
    set_server_env_vars();
    clear_path_secrets();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
    let cmd_dec_secret_dir = (*PJ_ROOT_DIR)
        .to_path_buf()
        .join(PathBuf::from_str(&*CMD_DEC_SECRET_DIR).unwrap());

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

    let erc20_server = ERC20Server::new(app_eid).await.use_treekem().run().await;
    let erc20_server = Arc::new(erc20_server);
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route("/api/v1/key_rotation", web::post().to(handle_key_rotation))
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            ),
    )
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

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    // check storing path_secret
    let id = get_local_id().unwrap();
    // local
    assert!(cmd_dec_secret_dir.join(&id).exists());
    // remote
    assert!(cmd_dec_secret_dir
        .join(env::var("MY_ROSTER_IDX").unwrap().as_str())
        .join(&id)
        .exists());

    // Init state
    let init_100_req = init_100_req(&mut csprng, &enc_key, 1);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    clear_local_path_secrets();
    // local
    assert!(!cmd_dec_secret_dir.join(&id).exists());
    // remote
    assert!(cmd_dec_secret_dir
        .join(env::var("MY_ROSTER_IDX").unwrap().as_str())
        .join(&id)
        .exists());

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_treekem_recover_without_key_vault() {
    set_env_vars();
    set_env_vars_for_treekem();
    set_server_env_vars();
    clear_path_secrets();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
    let cmd_dec_secret_dir = (*PJ_ROOT_DIR)
        .to_path_buf()
        .join(PathBuf::from_str(&*CMD_DEC_SECRET_DIR).unwrap());

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

    let erc20_server = ERC20Server::new(app_eid).await.use_treekem().run().await;
    let erc20_server = Arc::new(erc20_server);
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route("/api/v1/key_rotation", web::post().to(handle_key_rotation))
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            ),
    )
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

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    // check storing path_secret
    let id = get_local_id().unwrap();
    // local
    assert!(cmd_dec_secret_dir.join(&id).exists());
    // remote
    assert!(cmd_dec_secret_dir
        .join(env::var("MY_ROSTER_IDX").unwrap().as_str())
        .join(&id)
        .exists());

    // Init state
    let init_100_req = init_100_req(&mut csprng, &enc_key, 1);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    // stop key-vault server
    sgx_urts::rsgx_destroy_enclave(key_vault_server_eid).unwrap();

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_treekem_manually_backup_all() {
    set_env_vars();
    set_env_vars_for_treekem();
    set_server_env_vars();
    clear_path_secrets();

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

    let erc20_server = ERC20Server::new(app_eid).await.use_treekem().run().await;
    let erc20_server = Arc::new(erc20_server);
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route("/api/v1/key_rotation", web::post().to(handle_key_rotation))
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            )
            .route(
                "/api/v1/all_backup_to",
                web::post().to(handle_all_backup_to),
            ),
    )
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

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    // Init state
    let init_100_req = init_100_req(&mut csprng, &enc_key, 1);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    // check storing path_secret
    // local
    let local_ids = get_local_ids();
    assert_eq!(local_ids.len(), 2);
    // remote
    let remote_ids = get_remote_ids(env::var("MY_ROSTER_IDX").unwrap().to_string());
    assert_eq!(remote_ids.len(), 2);

    clear_remote_path_secrets(env::var("MY_ROSTER_IDX").unwrap().to_string());
    // ensure clearing remote path_secrets
    assert_eq!(
        get_remote_ids(env::var("MY_ROSTER_IDX").unwrap().to_string()).len(),
        0
    );

    // backup all path_secrets to key-vault server
    let req = test::TestRequest::post()
        .uri("/api/v1/all_backup_to")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    // check recovering remote path_secrets
    let recovered_remote_ids = get_remote_ids(env::var("MY_ROSTER_IDX").unwrap().to_string());
    assert_eq!(recovered_remote_ids, remote_ids);
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_treekem_manually_recover_all() {
    set_env_vars();
    set_env_vars_for_treekem();
    set_server_env_vars();
    clear_path_secrets();

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

    let erc20_server = ERC20Server::new(app_eid).await.use_treekem().run().await;
    let erc20_server = Arc::new(erc20_server);
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route("/api/v1/key_rotation", web::post().to(handle_key_rotation))
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            )
            .route(
                "/api/v1/all_backup_from",
                web::post().to(handle_all_backup_from),
            ),
    )
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

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    // Init state
    let init_100_req = init_100_req(&mut csprng, &enc_key, 1);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    // check storing path_secret
    // local
    let local_ids = get_local_ids();
    assert_eq!(local_ids.len(), 2);
    // remote
    let remote_ids = get_remote_ids(env::var("MY_ROSTER_IDX").unwrap().to_string());
    assert_eq!(remote_ids.len(), 2);

    clear_local_path_secrets();
    // ensure clearing remote path_secrets
    assert_eq!(get_local_ids().len(), 0);

    // recover all path_secrets from key-vault server
    let req = test::TestRequest::post()
        .uri("/api/v1/all_backup_from")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME + 500)).await;

    // check recovering local path_secrets
    let recovered_local_ids = get_local_ids();
    assert_eq!(recovered_local_ids, local_ids);
    assert!(!logs_contain("ERROR"));
}
