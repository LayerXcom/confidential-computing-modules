use crate::{handlers::*, Server};
use actix_web::{test, web, App};
use anonify_ecall_types::input;
use anonify_eth_driver::eth::*;
use ethabi::Contract as ContractABI;
use frame_common::crypto::{AccountId, Ed25519ChallengeResponse};
use frame_host::EnclaveDir;
use frame_runtime::primitives::U64;
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use integration_tests::set_env_vars;
use rand_core::{CryptoRng, RngCore};
use serde_json::json;
use std::{env, fs::File, io::BufReader, path::Path, str::FromStr, sync::Arc, time};
use web3::{
    contract::{Contract, Options},
    transports::Http,
    types::Address,
    Web3,
};

const SYNC_TIME: u64 = 1500;

#[actix_rt::test]
async fn test_deploy_post() {
    set_env_vars();
    set_server_env_vars();

    // Enclave must be initialized in main function.
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid));

    let mut app = test::init_service(App::new().data(server.clone()).route(
        "/api/v1/deploy",
        web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
    ))
    .await;

    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_address: state_runtime_node_api::deploy::post::Response =
        test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_address);
}

#[actix_rt::test]
async fn test_multiple_messages() {
    set_env_vars();
    set_server_env_vars();

    let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = &mut rand::rngs::OsRng;
    let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid));
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get()
                    .to(handle_enclave_encryption_key::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_address: state_runtime_node_api::deploy::post::Response =
        test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_address.contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &abi_path,
        &eth_url,
        &contract_address.contract_address,
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

    let init_100_req = init_100_req(&mut csprng, &enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let transfer_10_req = transfer_10_req(&mut csprng, &enc_key);
    // Sending five messages before receiving any messages
    for _ in 0..5 {
        let req = test::TestRequest::post()
            .uri("/api/v1/state")
            .set_json(&transfer_10_req)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success(), "response: {:?}", resp);
    }

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 50);
}

#[actix_rt::test]
async fn test_skip_invalid_event() {
    set_env_vars();
    set_server_env_vars();

    let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = &mut rand::rngs::OsRng;
    let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid));
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get()
                    .to(handle_enclave_encryption_key::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_address: state_runtime_node_api::deploy::post::Response =
        test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_address.contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/start_sync_bc")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &abi_path,
        &eth_url,
        &contract_address.contract_address,
    )
    .await;

    let init_100_req = init_100_req(&mut csprng, &enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let transfer_110_req = transfer_110_req(&mut csprng, &enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_110_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let transfer_10_req = transfer_10_req(&mut csprng, &enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);
}

#[actix_rt::test]
async fn test_node_recovery() {
    set_env_vars();
    set_server_env_vars();
    env::remove_var("AUDITOR_ENDPOINT");

    let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = &mut rand::rngs::OsRng;
    let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid));
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get()
                    .to(handle_enclave_encryption_key::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    let recovered_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let recovered_eid = recovered_enclave.geteid();
    let recovered_server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(
        recovered_eid,
    ));

    let mut recovered_app = test::init_service(
        App::new()
            .data(recovered_server.clone())
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get()
                    .to(handle_enclave_encryption_key::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/register_report",
                web::post().to(handle_register_report::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_address: state_runtime_node_api::deploy::post::Response =
        test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_address.contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/start_sync_bc")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &abi_path,
        &eth_url,
        &contract_address.contract_address,
    )
    .await;

    let init_100_req = init_100_req(&mut csprng, &enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let transfer_10_req_ = transfer_10_req(&mut csprng, &enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req_)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);

    // Assume the TEE node is down, and then recovered.

    my_turn();

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/register_report")
        .set_json(&state_runtime_node_api::register_report::post::Request {
            contract_address: contract_address.contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &abi_path,
        &eth_url,
        &contract_address.contract_address,
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);

    let transfer_10_req = transfer_10_req(&mut csprng, &enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req)
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 80);
}

#[actix_rt::test]
async fn test_join_group_then_handshake() {
    set_env_vars();
    set_server_env_vars();

    let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    // Enclave must be initialized in main function.
    let enclave1 = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid1 = enclave1.geteid();
    // just for testing
    let mut csprng = &mut rand::rngs::OsRng;
    let server1 = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid1));

    let mut app1 = test::init_service(
        App::new()
            .data(server1.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    let enclave2 = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid2 = enclave2.geteid();
    let server2 = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid2));

    let mut app2 = test::init_service(
        App::new()
            .data(server2.clone())
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/key_rotation",
                web::post().to(handle_key_rotation::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get()
                    .to(handle_enclave_encryption_key::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
    .await;

    // Party 1

    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_address: state_runtime_node_api::deploy::post::Response =
        test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_address.contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/start_sync_bc")
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // Party 2

    other_turn();

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/start_sync_bc")
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/join_group")
        .set_json(&state_runtime_node_api::join_group::post::Request {
            contract_address: contract_address.contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &abi_path,
        &eth_url,
        &contract_address.contract_address,
    )
    .await;

    let init_100_req = init_100_req(&mut csprng, &enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let transfer_10_req = transfer_10_req(&mut csprng, &enc_key);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);
}

fn set_server_env_vars() {
    env::set_var("ABI_PATH", "../../../contract-build/Anonify.abi");
    env::set_var("BIN_PATH", "../../../contract-build/Anonify.bin");
    env::set_var("CONFIRMATIONS", "0");
    env::set_var("ACCOUNT_INDEX", "0");
    env::set_var("PASSWORD", "anonify0101");
}

fn my_turn() {
    env::remove_var("MY_ROSTER_IDX");
    env::remove_var("ACCOUNT_INDEX");
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("ACCOUNT_INDEX", "0");
}

fn other_turn() {
    env::remove_var("MY_ROSTER_IDX");
    env::remove_var("ACCOUNT_INDEX");
    env::set_var("MY_ROSTER_IDX", "1");
    env::set_var("ACCOUNT_INDEX", "1");
}

async fn verify_enclave_encryption_key<P: AsRef<Path>>(
    enclave_encryption_key: SodiumPubKey,
    abi_path: P,
    eth_url: &str,
    contract_address: &str,
) -> SodiumPubKey {
    let transport = Http::new(eth_url).unwrap();
    let web3 = Web3::new(transport);
    let web3_conn = web3.eth();

    let address = Address::from_str(contract_address).unwrap();
    let f = File::open(abi_path).unwrap();
    let abi = ContractABI::load(BufReader::new(f)).unwrap();

    let query_enclave_encryption_key: Vec<u8> = Contract::new(web3_conn, address, abi)
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

// to me
fn init_100_req<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
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
    let init_100 = json!({
        "total_supply": U64::from_raw(100),
    });
    let req = input::Command::new(access_policy, init_100, "construct");
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request { ciphertext }
}

// from me to other
fn transfer_10_req<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
) -> state_runtime_node_api::state::post::Request
where
    CR: RngCore + CryptoRng,
{
    let sig = [
        227, 77, 52, 167, 149, 64, 24, 23, 103, 227, 13, 120, 90, 186, 1, 62, 110, 60, 186, 247,
        143, 247, 19, 71, 85, 191, 224, 5, 38, 219, 96, 44, 196, 154, 181, 50, 99, 58, 20, 125,
        244, 172, 212, 166, 234, 203, 208, 77, 9, 232, 77, 248, 152, 81, 106, 49, 120, 34, 212, 89,
        92, 100, 221, 14,
    ];
    let pubkey = [
        164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33, 189,
        55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
    ];
    let challenge = [
        157, 61, 16, 189, 40, 124, 88, 101, 19, 36, 155, 229, 245, 123, 189, 124, 222, 114, 215,
        186, 25, 30, 135, 114, 237, 169, 138, 122, 81, 61, 43, 183,
    ];
    let access_policy = Ed25519ChallengeResponse::new_from_bytes(sig, pubkey, challenge);
    let transfer_10 = json!({
        "amount": U64::from_raw(10),
        "recipient": AccountId([
            236, 126, 92, 200, 50, 125, 9, 112, 74, 58, 35, 60, 181, 105, 198, 107, 62, 111, 168,
            118,
        ])
    });
    let req = input::Command::new(access_policy, transfer_10, "transfer");
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request { ciphertext }
}

// from me to other
fn transfer_110_req<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
) -> state_runtime_node_api::state::post::Request
where
    CR: RngCore + CryptoRng,
{
    let sig = [
        227, 77, 52, 167, 149, 64, 24, 23, 103, 227, 13, 120, 90, 186, 1, 62, 110, 60, 186, 247,
        143, 247, 19, 71, 85, 191, 224, 5, 38, 219, 96, 44, 196, 154, 181, 50, 99, 58, 20, 125,
        244, 172, 212, 166, 234, 203, 208, 77, 9, 232, 77, 248, 152, 81, 106, 49, 120, 34, 212, 89,
        92, 100, 221, 14,
    ];
    let pubkey = [
        164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33, 189,
        55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
    ];
    let challenge = [
        157, 61, 16, 189, 40, 124, 88, 101, 19, 36, 155, 229, 245, 123, 189, 124, 222, 114, 215,
        186, 25, 30, 135, 114, 237, 169, 138, 122, 81, 61, 43, 183,
    ];
    let access_policy = Ed25519ChallengeResponse::new_from_bytes(sig, pubkey, challenge);
    let transfer_10 = json!({
        "amount": U64::from_raw(110),
        "recipient": AccountId([
            236, 126, 92, 200, 50, 125, 9, 112, 74, 58, 35, 60, 181, 105, 198, 107, 62, 111, 168,
            118,
        ])
    });
    let req = input::Command::new(access_policy, transfer_10, "transfer");
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request { ciphertext }
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
        SodiumCiphertext::encrypt(csprng, &enc_key, serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::get::Request { ciphertext }
}
