use crate::{api, handlers::*, Server as KeyVaultServer};
use actix_web::{test, web, App};
use anonify_config::PJ_ROOT_DIR;
use anonify_eth_driver::eth::{EthDeployer, EthSender, EventWatcher};
use codec::{Decode, Encode};
use erc20_server::{handlers::*, Server as ERC20Server};
use erc20_state_transition::construct;
use ethabi::Contract as ContractABI;
use frame_host::EnclaveDir;
use frame_runtime::primitives::U64;
use frame_treekem::{DhPubKey, EciesCiphertext};
use once_cell::sync::Lazy;
use std::{
    env,
    fs::{self, File},
    io::BufReader,
    path::Path,
    str::FromStr,
    sync::Arc,
};
use web3::{
    contract::{Contract, Options},
    transports::Http,
    types::Address,
    Web3,
};

#[actix_rt::test]
async fn test_backup_path_secret() {
    set_env_vars();
    set_server_env_vars();
    clear_path_secrets();

    let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    // Setup key-vault server
    let key_vault_server_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize server enclave.");
    let key_vault_server_eid = key_vault_server_enclave.geteid();
    let key_vault_server = Arc::new(KeyVaultServer::new(key_vault_server_eid));

    let mut key_vault_app = test::init_service(
        App::new()
            .data(key_vault_server.clone())
            .route("/api/v1/start", web::post().to(handle_start))
            .route("/api/v1/stop", web::post().to(handle_stop)),
    )
    .await;

    let req = test::TestRequest::post().uri("/api/v1/start").to_request();
    let resp = test::call_service(&mut key_vault_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let start_response: api::start::post::Response = test::read_body_json(resp).await;
    assert_eq!(start_response.status, "success".to_string());

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Setup ERC20 application
    env::set_var("ENCLAVE_PKG_NAME", "erc20");
    let app_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize client enclave.");
    let app_eid = app_enclave.geteid();

    let erc20_server = Arc::new(ERC20Server::<EthDeployer, EthSender, EventWatcher>::new(
        app_eid,
    ));
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/init_state",
                web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/key_rotation",
                web::post().to(handle_key_rotation::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/encrypting_key",
                web::get().to(handle_encrypting_key::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    // Ensure not to exist path_secret directory on both local and remote
    let path_secrets_dir =
        PJ_ROOT_DIR.join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set"));
    assert!(!path_secrets_dir.exists());

    // Deploy
    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_addr: erc20_api::deploy::post::Response = test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_addr.0);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 0);

    let req = test::TestRequest::get()
        .uri("/api/v1/encrypting_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let enc_key_resp: erc20_api::encrypting_key::get::Response = test::read_body_json(resp).await;
    let enc_key =
        verify_encrypting_key(enc_key_resp.0, &abi_path, &eth_url, &contract_addr.0).await;

    // check storing path_secret
    let id = get_local_id().unwrap();
    // local
    assert!(path_secrets_dir.join(&id).exists());
    // remote
    assert!(path_secrets_dir
        .join(env::var("MY_ROSTER_IDX").unwrap().as_str())
        .join(&id)
        .exists());

    // Init state
    let init_100_req = init_100_req(&enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/init_state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    clear_local_path_secrets();
    // local
    assert!(!path_secrets_dir.join(&id).exists());
    // remote
    assert!(path_secrets_dir
        .join(env::var("MY_ROSTER_IDX").unwrap().as_str())
        .join(&id)
        .exists());

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 100);
}

#[actix_rt::test]
async fn test_recover_without_key_vault() {
    set_env_vars();
    set_server_env_vars();
    clear_path_secrets();

    let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    // Setup key-vault server
    let key_vault_server_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize server enclave.");
    let key_vault_server_eid = key_vault_server_enclave.geteid();
    let key_vault_server = Arc::new(KeyVaultServer::new(key_vault_server_eid));

    let mut key_vault_app = test::init_service(
        App::new()
            .data(key_vault_server.clone())
            .route("/api/v1/start", web::post().to(handle_start))
            .route("/api/v1/stop", web::post().to(handle_stop)),
    )
    .await;

    let req = test::TestRequest::post().uri("/api/v1/start").to_request();
    let resp = test::call_service(&mut key_vault_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let start_response: api::start::post::Response = test::read_body_json(resp).await;
    assert_eq!(start_response.status, "success".to_string());

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Setup ERC20 application
    env::set_var("ENCLAVE_PKG_NAME", "erc20");
    let app_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize client enclave.");
    let app_eid = app_enclave.geteid();

    let erc20_server = Arc::new(ERC20Server::<EthDeployer, EthSender, EventWatcher>::new(
        app_eid,
    ));
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/init_state",
                web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/key_rotation",
                web::post().to(handle_key_rotation::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/encrypting_key",
                web::get().to(handle_encrypting_key::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    // Ensure not to exist path_secret directory on both local and remote
    let path_secrets_dir =
        PJ_ROOT_DIR.join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set"));
    assert!(!path_secrets_dir.exists());

    // Deploy
    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_addr: erc20_api::deploy::post::Response = test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_addr.0);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 0);

    let req = test::TestRequest::get()
        .uri("/api/v1/encrypting_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let enc_key_resp: erc20_api::encrypting_key::get::Response = test::read_body_json(resp).await;
    let enc_key =
        verify_encrypting_key(enc_key_resp.0, &abi_path, &eth_url, &contract_addr.0).await;

    // check storing path_secret
    let id = get_local_id().unwrap();
    // local
    assert!(path_secrets_dir.join(&id).exists());
    // remote
    assert!(path_secrets_dir
        .join(env::var("MY_ROSTER_IDX").unwrap().as_str())
        .join(&id)
        .exists());

    // Init state
    let init_100_req = init_100_req(&enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/init_state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // stop key-vault server
    sgx_urts::rsgx_destroy_enclave(key_vault_server_eid).unwrap();

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 100);
}

#[actix_rt::test]
async fn test_manually_backup_all() {
    set_env_vars();
    set_server_env_vars();
    clear_path_secrets();

    let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    // Setup key-vault server
    let key_vault_server_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize server enclave.");
    let key_vault_server_eid = key_vault_server_enclave.geteid();
    let key_vault_server = Arc::new(KeyVaultServer::new(key_vault_server_eid));

    let mut key_vault_app = test::init_service(
        App::new()
            .data(key_vault_server.clone())
            .route("/api/v1/start", web::post().to(handle_start))
            .route("/api/v1/stop", web::post().to(handle_stop)),
    )
    .await;

    let req = test::TestRequest::post().uri("/api/v1/start").to_request();
    let resp = test::call_service(&mut key_vault_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let start_response: api::start::post::Response = test::read_body_json(resp).await;
    assert_eq!(start_response.status, "success".to_string());

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Setup ERC20 application
    env::set_var("ENCLAVE_PKG_NAME", "erc20");
    let app_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize client enclave.");
    let app_eid = app_enclave.geteid();

    let erc20_server = Arc::new(ERC20Server::<EthDeployer, EthSender, EventWatcher>::new(
        app_eid,
    ));
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/init_state",
                web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/key_rotation",
                web::post().to(handle_key_rotation::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/encrypting_key",
                web::get().to(handle_encrypting_key::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/all_backup_to",
                web::post().to(handle_all_backup_to::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    // Ensure not to exist path_secret directory on both local and remote
    let path_secrets_dir =
        PJ_ROOT_DIR.join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set"));
    assert!(!path_secrets_dir.exists());

    // Deploy
    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_addr: erc20_api::deploy::post::Response = test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_addr.0);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 0);

    let req = test::TestRequest::get()
        .uri("/api/v1/encrypting_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let enc_key_resp: erc20_api::encrypting_key::get::Response = test::read_body_json(resp).await;
    let enc_key =
        verify_encrypting_key(enc_key_resp.0, &abi_path, &eth_url, &contract_addr.0).await;

    // Init state
    let init_100_req = init_100_req(&enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/init_state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 100);

    // check storing path_secret
    // local
    let local_ids = get_local_ids();
    assert_eq!(local_ids.len(), 2);
    // remote
    let remote_ids = get_remote_ids(env::var("MY_ROSTER_IDX").unwrap().to_string());
    assert_eq!(remote_ids.len(), 2);

    clear_remote_path_secrets(env::var("MY_ROSTER_IDX").unwrap().to_string());
    // ensure clearing remote path_secrets
    assert!(!path_secrets_dir
        .join(env::var("MY_ROSTER_IDX").unwrap().as_str())
        .exists());

    // backup all path_secrets to key-vault server
    let req = test::TestRequest::post()
        .uri("/api/v1/all_backup_to")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // check recovering remote path_secrets
    let recovered_remote_ids = get_remote_ids(env::var("MY_ROSTER_IDX").unwrap().to_string());
    assert_eq!(recovered_remote_ids, remote_ids);
}

#[actix_rt::test]
async fn test_manually_recover_all() {
    set_env_vars();
    set_server_env_vars();
    clear_path_secrets();

    let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    // Setup key-vault server
    let key_vault_server_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize server enclave.");
    let key_vault_server_eid = key_vault_server_enclave.geteid();
    let key_vault_server = Arc::new(KeyVaultServer::new(key_vault_server_eid));

    let mut key_vault_app = test::init_service(
        App::new()
            .data(key_vault_server.clone())
            .route("/api/v1/start", web::post().to(handle_start))
            .route("/api/v1/stop", web::post().to(handle_stop)),
    )
    .await;

    let req = test::TestRequest::post().uri("/api/v1/start").to_request();
    let resp = test::call_service(&mut key_vault_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let start_response: api::start::post::Response = test::read_body_json(resp).await;
    assert_eq!(start_response.status, "success".to_string());

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Setup ERC20 application
    env::set_var("ENCLAVE_PKG_NAME", "erc20");
    let app_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize client enclave.");
    let app_eid = app_enclave.geteid();

    let erc20_server = Arc::new(ERC20Server::<EthDeployer, EthSender, EventWatcher>::new(
        app_eid,
    ));
    let mut app = test::init_service(
        App::new()
            .data(erc20_server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/init_state",
                web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/key_rotation",
                web::post().to(handle_key_rotation::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/encrypting_key",
                web::get().to(handle_encrypting_key::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/all_backup_from",
                web::post().to(handle_all_backup_from::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    // Ensure not to exist path_secret directory on both local and remote
    let path_secrets_dir =
        PJ_ROOT_DIR.join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set"));
    assert!(!path_secrets_dir.exists());

    // Deploy
    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_addr: erc20_api::deploy::post::Response = test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_addr.0);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 0);

    let req = test::TestRequest::get()
        .uri("/api/v1/encrypting_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let enc_key_resp: erc20_api::encrypting_key::get::Response = test::read_body_json(resp).await;
    let enc_key =
        verify_encrypting_key(enc_key_resp.0, &abi_path, &eth_url, &contract_addr.0).await;

    // Init state
    let init_100_req = init_100_req(&enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/init_state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 100);

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

    // check recovering local path_secrets
    let recovered_local_ids = get_local_ids();
    assert_eq!(recovered_local_ids, local_ids);
}

pub static SUBSCRIBER_INIT: Lazy<()> = Lazy::new(|| {
    tracing_subscriber::fmt::init();
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
    env::set_var("KEY_VAULT_ENDPOINT", "localhost:12345");
    env::set_var("ENCLAVE_PKG_NAME", "secret_backup");
    env::set_var("PATH_SECRETS_DIR", ".anonify/pathsecrets");
}

fn set_server_env_vars() {
    env::set_var("ETH_URL", "http://172.28.0.2:8545");
    env::set_var("ABI_PATH", "../../../contract-build/Anonify.abi");
    env::set_var("BIN_PATH", "../../../contract-build/Anonify.bin");
    env::set_var("CONFIRMATIONS", "0");
    env::set_var("ACCOUNT_INDEX", "0");
    env::set_var("PASSWORD", "anonify0101");
}

fn clear_local_path_secrets() {
    let target_dir =
        PJ_ROOT_DIR.join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set"));
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
        .join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set"))
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
        PJ_ROOT_DIR.join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set"));
    if target.exists() {
        fs::remove_dir_all(target).unwrap();
    }
}

fn get_local_id() -> Option<String> {
    let paths = fs::read_dir(
        PJ_ROOT_DIR.join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set")),
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
        PJ_ROOT_DIR.join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set")),
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
            .join(&env::var("PATH_SECRETS_DIR").expect("PATH_SECRETS_DIR is not set"))
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

async fn verify_encrypting_key<P: AsRef<Path>>(
    encrypting_key: DhPubKey,
    abi_path: P,
    eth_url: &str,
    contract_addr: &str,
) -> DhPubKey {
    let transport = Http::new(eth_url).unwrap();
    let web3 = Web3::new(transport);
    let web3_conn = web3.eth();

    let address = Address::from_str(contract_addr).unwrap();
    let f = File::open(abi_path).unwrap();
    let abi = ContractABI::load(BufReader::new(f)).unwrap();

    let query_encrypting_key: Vec<u8> = Contract::new(web3_conn, address, abi)
        .query(
            "getEncryptingKey",
            encrypting_key.encode(),
            None,
            Options::default(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        encrypting_key,
        DhPubKey::decode(&mut &query_encrypting_key[..]).unwrap()
    );

    encrypting_key
}

fn init_100_req(enc_key: &DhPubKey) -> erc20_api::init_state::post::Request {
    let init_100 = construct {
        total_supply: U64::from_raw(100),
    };
    let enc_cmd = EciesCiphertext::encrypt(&enc_key, init_100.encode()).unwrap();

    erc20_api::init_state::post::Request {
        sig: [
            236, 103, 17, 252, 166, 199, 9, 46, 200, 107, 188, 0, 37, 111, 83, 105, 175, 81, 231,
            14, 81, 100, 221, 89, 102, 172, 30, 96, 15, 128, 117, 146, 181, 221, 149, 206, 163,
            208, 113, 198, 241, 16, 150, 248, 99, 170, 85, 122, 165, 197, 14, 120, 110, 37, 69, 32,
            36, 218, 100, 64, 224, 226, 99, 2,
        ],
        pubkey: [
            164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33,
            189, 55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
        ],
        challenge: [
            244, 158, 183, 202, 237, 236, 27, 67, 39, 95, 178, 136, 235, 162, 188, 106, 52, 56, 6,
            245, 3, 101, 33, 155, 58, 175, 168, 63, 73, 125, 205, 225,
        ],
        encrypted_total_supply: enc_cmd,
    }
}

const BALANCE_OF_REQ: erc20_api::state::get::Request = erc20_api::state::get::Request {
    sig: [
        21, 54, 136, 84, 150, 59, 196, 71, 164, 136, 222, 128, 100, 84, 208, 219, 84, 7, 61, 11,
        230, 220, 25, 138, 67, 247, 95, 97, 30, 76, 120, 160, 73, 48, 110, 43, 94, 79, 192, 195,
        82, 199, 73, 80, 48, 148, 233, 143, 87, 237, 159, 97, 252, 226, 68, 160, 137, 127, 195,
        116, 128, 181, 47, 2,
    ],
    pubkey: [
        164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33, 189,
        55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
    ],
    challenge: [
        119, 177, 182, 220, 100, 44, 96, 179, 173, 47, 220, 49, 105, 204, 132, 230, 211, 24, 166,
        219, 82, 76, 27, 205, 211, 232, 142, 98, 66, 130, 150, 202,
    ],
};
