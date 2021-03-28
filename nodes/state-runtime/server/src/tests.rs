use crate::{handlers::*, Server};
use actix_web::{http::StatusCode, test, web, App};
use anonify_eth_driver::utils::*;
use frame_common::{
    crypto::{AccountId, Ed25519ChallengeResponse},
    AccessPolicy,
};
use frame_config::{ANONIFY_ABI_PATH, FACTORY_ABI_PATH};
use frame_host::EnclaveDir;
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use integration_tests::set_env_vars;
use rand_core::{CryptoRng, RngCore};
use serde_json::json;
use std::{env, path::Path, str::FromStr, sync::Arc, time};
use web3::{contract::Options, types::Address};

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
}

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

    let server = Server::new(eid).await.run().await;
    let server = Arc::new(server);
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
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

    let server = Server::new(eid).await.run().await;
    let server = Arc::new(server);
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
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

    let server = Server::new(eid).await.run().await;
    let server = Arc::new(server);
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
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

    let server = Server::new(eid).await.run().await;
    let server = Arc::new(server);
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            ),
    )
    .await;

    let recovered_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let recovered_eid = recovered_enclave.geteid();

    // Do not run
    let recovered_server = Arc::new(Server::new(recovered_eid).await);

    let mut recovered_app = test::init_service(
        App::new()
            .data(recovered_server.clone())
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            )
            .route(
                "/api/v1/register_report",
                web::post().to(handle_register_report),
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

    let req = test::TestRequest::post()
        .uri("/api/v1/register_report")
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
        &*FACTORY_ABI_PATH,
        &*ANONIFY_ABI_PATH,
        &eth_url,
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

    let server1 = Server::new(eid1).await.run().await;
    let server1 = Arc::new(server1);
    let mut app1 = test::init_service(
        App::new()
            .data(server1.clone())
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            ),
    )
    .await;

    env::set_var("MY_ROSTER_IDX", "1");
    let enclave2 = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid2 = enclave2.geteid();
    let server2 = Server::new(eid2).await.run().await;
    let server2 = Arc::new(server2);
    let mut app2 = test::init_service(
        App::new()
            .data(server2.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route("/api/v1/key_rotation", web::post().to(handle_key_rotation))
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            ),
    )
    .await;

    // Party 1

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let enc_key_resp: state_runtime_node_api::enclave_encryption_key::get::Response =
        test::read_body_json(resp).await;
    let enc_key1 = verify_enclave_encryption_key(
        enc_key_resp.enclave_encryption_key,
        &*FACTORY_ABI_PATH,
        &*ANONIFY_ABI_PATH,
        &eth_url,
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

    env::set_var("ACCOUNT_INDEX", "1");

    // using the same encryption key because app2 have to sync with bc, but app2's enclave encryption key cannot be set here
    // so using app1's key
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key1))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp); // return 200 OK: becuse allowed same enclave encryption key

    let req = test::TestRequest::get()
        .uri("/api/v1/enclave_encryption_key")
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
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

    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    // Requests from party 2
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

    // Request from other via state-runtime 1
    let transfer_other_5_req = transfer_other_5_req(&mut csprng, &enc_key, 1, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_other_5_req)
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // check the result of state transition in state-runtime 1
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_other_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 5);

    // check the result of state transition in state-runtime 2
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_other_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 5);

    // Request from other via state-runtime 2
    let transfer_other_5_req = transfer_other_5_req(&mut csprng, &enc_key, 2, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_other_5_req)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // check the result of state transition in state-runtime 1
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_other_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    // check the result of state transition in state-runtime 2
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_other_req(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);
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

    let server = Server::new(eid).await.run().await;
    let server = Arc::new(server);
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route(
                "/api/v1/user_counter",
                web::get().to(handle_get_user_counter),
            )
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

fn valid_other_user_id() -> AccountId {
    let sig = [
        227, 214, 246, 7, 62, 33, 159, 246, 238, 120, 63, 85, 220, 132, 207, 133, 93, 74, 35, 180,
        99, 85, 57, 254, 2, 205, 175, 221, 61, 86, 246, 86, 229, 86, 19, 47, 46, 46, 66, 4, 186,
        245, 251, 191, 16, 3, 40, 107, 179, 53, 172, 131, 113, 117, 2, 65, 119, 174, 54, 248, 146,
        13, 20, 13,
    ];
    let pubkey = [
        123, 153, 87, 235, 253, 48, 23, 28, 250, 137, 255, 93, 230, 42, 139, 136, 203, 222, 179,
        160, 141, 51, 10, 36, 197, 59, 62, 211, 95, 25, 255, 111,
    ];
    let challenge = [
        196, 164, 228, 172, 9, 251, 94, 245, 43, 74, 182, 98, 47, 59, 145, 40, 28, 65, 122, 189,
        150, 211, 16, 29, 204, 200, 52, 116, 106, 234, 138, 139,
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
fn transfer_10_req<CR>(
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
            "recipient": valid_other_user_id(),
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
fn transfer_other_5_req<CR>(
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
            "recipient": valid_user_id(),
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
fn transfer_110_req<CR>(
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
            "recipient": valid_other_user_id(),
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

fn balance_of_req<CR>(
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

fn balance_of_other_req<CR>(
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

fn user_counter_req<CR>(
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
