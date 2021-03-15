use crate::{handlers::*, Server};
use actix_web::{test, web, App};
use anonify_eth_driver::eth::*;
use eth_deployer::EthDeployer;
use ethabi::Contract as ContractABI;
use frame_common::{
    crypto::{AccountId, Ed25519ChallengeResponse},
    AccessPolicy,
};
use frame_config::{ANONIFY_ABI_PATH, ANONIFY_BIN_PATH};
use frame_host::EnclaveDir;
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
const GAS: u64 = 5_000_000;

#[actix_rt::test]
async fn test_evaluate_access_policy_by_user_id_field() {
    set_env_vars();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let server = Arc::new(Server::<EthSender, EventWatcher>::new(eid));
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key::<EthSender, EventWatcher>),
            ),
    )
    .await;

    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer.get_account(0usize, None).await.unwrap();
    let contract_address = deployer
        .deploy(&*ANONIFY_ABI_PATH, &*ANONIFY_BIN_PATH, 0usize, GAS, signer)
        .await
        .unwrap();
    println!("contract address: {:?}", contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/join_group")
        .set_json(&state_runtime_node_api::join_group::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*ANONIFY_ABI_PATH,
        &eth_url,
        &contract_address,
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

    let init_100_req = init_100_req(&mut csprng, &enc_key, 1, Some(valid_user_id()));
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

    // Sending valid user_id, so this request should be successful
    let transfer_10_req_json = transfer_10_req(&mut csprng, &enc_key, 2, Some(valid_user_id()));
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req_json)
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

    // Sending invalid user_id, so this request should be failed
    let transfer_10_req_json = transfer_10_req(&mut csprng, &enc_key, 3, Some(INVALID_USER_ID));
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req_json)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_server_error(), "response: {:?}", resp);

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
async fn test_multiple_messages() {
    set_env_vars();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let server = Arc::new(Server::<EthSender, EventWatcher>::new(eid));
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key::<EthSender, EventWatcher>),
            ),
    )
    .await;

    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer.get_account(0usize, None).await.unwrap();
    let contract_address = deployer
        .deploy(&*ANONIFY_ABI_PATH, &*ANONIFY_BIN_PATH, 0usize, GAS, signer)
        .await
        .unwrap();
    println!("contract address: {:?}", contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/join_group")
        .set_json(&state_runtime_node_api::join_group::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*ANONIFY_ABI_PATH,
        &eth_url,
        &contract_address,
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

    let init_100_req = init_100_req(&mut csprng, &enc_key, 1, None);
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

    // Sending five messages before receiving any messages
    for i in 0..5 {
        let transfer_10_req = transfer_10_req(&mut csprng, &enc_key, 2 + i, None);
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

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let server = Arc::new(Server::<EthSender, EventWatcher>::new(eid));
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key::<EthSender, EventWatcher>),
            ),
    )
    .await;

    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer.get_account(0usize, None).await.unwrap();
    let contract_address = deployer
        .deploy(&*ANONIFY_ABI_PATH, &*ANONIFY_BIN_PATH, 0usize, GAS, signer)
        .await
        .unwrap();
    println!("contract address: {:?}", contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/join_group")
        .set_json(&state_runtime_node_api::join_group::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*ANONIFY_ABI_PATH,
        &eth_url,
        &contract_address,
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

    let init_100_req = init_100_req(&mut csprng, &enc_key, 1, None);
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

    // state transition should not be occured by this transaction.
    let transfer_110_req = transfer_110_req(&mut csprng, &enc_key, 2, None);
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

    let transfer_10_req = transfer_10_req(&mut csprng, &enc_key, 3, None);
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

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let server = Arc::new(Server::<EthSender, EventWatcher>::new(eid));
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key::<EthSender, EventWatcher>),
            ),
    )
    .await;

    let recovered_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let recovered_eid = recovered_enclave.geteid();
    let recovered_server = Arc::new(Server::<EthSender, EventWatcher>::new(recovered_eid));

    let mut recovered_app = test::init_service(
        App::new()
            .data(recovered_server.clone())
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/register_report",
                web::post().to(handle_register_report::<EthSender, EventWatcher>),
            ),
    )
    .await;

    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer.get_account(0usize, None).await.unwrap();
    let contract_address = deployer
        .deploy(&*ANONIFY_ABI_PATH, &*ANONIFY_BIN_PATH, 0usize, GAS, signer)
        .await
        .unwrap();
    println!("contract address: {:?}", contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/join_group")
        .set_json(&state_runtime_node_api::join_group::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*ANONIFY_ABI_PATH,
        &eth_url,
        &contract_address,
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

    let init_100_req = init_100_req(&mut csprng, &enc_key, 1, None);
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

    let transfer_10_req_ = transfer_10_req(&mut csprng, &enc_key, 2, None);
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
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/register_report")
        .set_json(&state_runtime_node_api::register_report::post::Request {
            contract_address: contract_address.clone(),
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
        &*ANONIFY_ABI_PATH,
        &eth_url,
        &contract_address,
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

    let transfer_10_req = transfer_10_req(&mut csprng, &enc_key, 3, None);
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

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    // Enclave must be initialized in main function.
    let enclave1 = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid1 = enclave1.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let server1 = Arc::new(Server::<EthSender, EventWatcher>::new(eid1));

    let mut app1 = test::init_service(
        App::new()
            .data(server1.clone())
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key::<EthSender, EventWatcher>),
            ),
    )
    .await;

    let enclave2 = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid2 = enclave2.geteid();
    let server2 = Arc::new(Server::<EthSender, EventWatcher>::new(eid2));

    let mut app2 = test::init_service(
        App::new()
            .data(server2.clone())
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/key_rotation",
                web::post().to(handle_key_rotation::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key::<EthSender, EventWatcher>),
            ),
    )
    .await;

    // Party 1

    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer.get_account(0usize, None).await.unwrap();
    let contract_address = deployer
        .deploy(&*ANONIFY_ABI_PATH, &*ANONIFY_BIN_PATH, 0usize, GAS, signer)
        .await
        .unwrap();
    println!("contract address: {:?}", contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/join_group")
        .set_json(&state_runtime_node_api::join_group::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key1 = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*ANONIFY_ABI_PATH,
        &eth_url,
        &contract_address,
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key1))
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    // Party 2

    other_turn();

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // using the same encryption key because app2 have to sync with bc, but app2's enclave encryption key cannot be set here
    // so using app1's key
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key1))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp); // return 200 OK: becuse allowed same enclave encryption key

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/join_group")
        .set_json(&state_runtime_node_api::join_group::post::Request {
            contract_address: contract_address.clone(),
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
        &*ANONIFY_ABI_PATH,
        &eth_url,
        &contract_address,
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    let init_100_req = init_100_req(&mut csprng, &enc_key, 1, None);
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

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let transfer_10_req = transfer_10_req(&mut csprng, &enc_key, 2, None);
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

#[actix_rt::test]
async fn test_duplicated_out_of_order_request_from_same_user() {
    set_env_vars();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let server = Arc::new(Server::<EthSender, EventWatcher>::new(eid));
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/user_counter",
                web::get().to(handle_get_user_counter::<EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key::<EthSender, EventWatcher>),
            ),
    )
    .await;

    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer.get_account(0usize, None).await.unwrap();
    let contract_address = deployer
        .deploy(&*ANONIFY_ABI_PATH, &*ANONIFY_BIN_PATH, 0usize, GAS, signer)
        .await
        .unwrap();
    println!("contract address: {:?}", contract_address);

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_address")
        .set_json(&state_runtime_node_api::contract_addr::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/join_group")
        .set_json(&state_runtime_node_api::join_group::post::Request {
            contract_address: contract_address.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*ANONIFY_ABI_PATH,
        &eth_url,
        &contract_address,
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/user_counter")
        .set_json(&user_counter_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let user_counter: state_runtime_node_api::user_counter::get::Response =
        test::read_body_json(resp).await;
    assert_eq!(user_counter.user_counter, 0);

    let init_100_req = init_100_req(
        &mut csprng,
        &enc_key,
        user_counter.user_counter.as_u64().unwrap() as u32 + 1,
        None,
    );
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

    let req = test::TestRequest::get()
        .uri("/api/v1/user_counter")
        .set_json(&user_counter_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let user_counter: state_runtime_node_api::user_counter::get::Response =
        test::read_body_json(resp).await;
    assert_eq!(user_counter.user_counter, 1);

    // first request
    let transfer_10 = transfer_10_req(
        &mut csprng,
        &enc_key,
        user_counter.user_counter.as_u64().unwrap() as u32 + 1,
        None,
    );
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10)
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
    assert_eq!(balance.state, 90); // success

    let req = test::TestRequest::get()
        .uri("/api/v1/user_counter")
        .set_json(&user_counter_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let user_counter: state_runtime_node_api::user_counter::get::Response =
        test::read_body_json(resp).await;
    assert_eq!(user_counter.user_counter, 2);

    // try second duplicated request
    let transfer_10 = transfer_10_req(
        &mut csprng,
        &enc_key,
        user_counter.user_counter.as_u64().unwrap() as u32,
        None,
    ); // same counter
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10)
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
    assert_eq!(balance.state, 90); // failed

    // send out of order request
    let transfer_10 = transfer_10_req(
        &mut csprng,
        &enc_key,
        user_counter.user_counter.as_u64().unwrap() as u32 + 2, // should be 3
        None,
    );
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10)
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
    assert_eq!(balance.state, 90); // failed

    // then, send correct request
    let transfer_10 = transfer_10_req(
        &mut csprng,
        &enc_key,
        user_counter.user_counter.as_u64().unwrap() as u32 + 1,
        None,
    );
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10)
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
    assert_eq!(balance.state, 80); // success
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

const INVALID_USER_ID: AccountId = AccountId([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
]);

fn valid_user_id() -> AccountId {
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
    Ed25519ChallengeResponse::new_from_bytes(sig, pubkey, challenge).into_account_id()
}

// to me
fn init_100_req<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
    counter: u32,
    user_id: Option<AccountId>,
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
        SodiumCiphertext::encrypt(csprng, &enc_key, serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request {
        ciphertext,
        user_id,
    }
}

// from me to other
fn transfer_10_req<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
    counter: u32,
    user_id: Option<AccountId>,
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

    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "amount": 10,
            "recipient": AccountId([
                236, 126, 92, 200, 50, 125, 9, 112, 74, 58, 35, 60, 181, 105, 198, 107, 62, 111, 168,
                118,
            ])
        },
        "cmd_name": "transfer",
        "counter": counter,
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request {
        ciphertext,
        user_id,
    }
}

// from me to other
fn transfer_110_req<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
    counter: u32,
    user_id: Option<AccountId>,
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

    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "amount": 110,
            "recipient": AccountId([
                236, 126, 92, 200, 50, 125, 9, 112, 74, 58, 35, 60, 181, 105, 198, 107, 62, 111, 168,
                118,
            ])
        },
        "cmd_name": "transfer",
        "counter": counter,
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::post::Request {
        ciphertext,
        user_id,
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
        SodiumCiphertext::encrypt(csprng, &enc_key, serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::state::get::Request { ciphertext }
}

fn user_counter_req<CR>(
    csprng: &mut CR,
    enc_key: &SodiumPubKey,
) -> state_runtime_node_api::user_counter::get::Request
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
    });
    let ciphertext =
        SodiumCiphertext::encrypt(csprng, &enc_key, serde_json::to_vec(&req).unwrap()).unwrap();

    state_runtime_node_api::user_counter::get::Request { ciphertext }
}
