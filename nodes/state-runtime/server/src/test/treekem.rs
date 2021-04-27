use crate::{handlers::*, Server};
use actix_web::{test, web, App};
use frame_common::AccessPolicy;
use frame_config::{ANONIFY_ABI_PATH, FACTORY_ABI_PATH};
use frame_host::EnclaveDir;
use integration_tests::{set_env_vars, set_env_vars_for_treekem};
use std::{env, sync::Arc, time};
#[cfg(test)]
use test_utils::tracing::{logs_clear, logs_contain};

use super::*;

#[actix_rt::test]
async fn test_treekem_evaluate_access_policy_by_user_id_field() {
    set_env_vars();
    set_env_vars_for_treekem();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();

    let server = Server::new(eid).await.use_treekem().run().await;
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    let init_100_req = init_100_req_fn(
        &mut csprng,
        &enc_key,
        1,
        Some(valid_user_id().into_account_id()),
    );
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    // Sending valid user_id, so this request should be successful
    let transfer_10_req_json = transfer_10_req_fn(
        &mut csprng,
        &enc_key,
        2,
        Some(valid_user_id().into_account_id()),
    );
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req_json)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);

    // Sending invalid user_id, so this request should be failed
    logs_clear();
    let transfer_10_req_json = transfer_10_req_fn(&mut csprng, &enc_key, 3, Some(INVALID_USER_ID));
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req_json)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_server_error(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);
    assert!(logs_contain("Internal Server Error")); // Invalid user_id. user_id in the ciphertext
}

#[actix_rt::test]
async fn test_treekem_multiple_messages() {
    set_env_vars();
    set_env_vars_for_treekem();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();

    let server = Server::new(eid).await.use_treekem().run().await;
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    let init_100_req = init_100_req_fn(&mut csprng, &enc_key, 1, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    // Sending five messages before receiving any messages
    for i in 0..5 {
        let transfer_10_req = transfer_10_req_fn(&mut csprng, &enc_key, 2 + i, None);
        let req = test::TestRequest::post()
            .uri("/api/v1/state")
            .set_json(&transfer_10_req)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success(), "response: {:?}", resp);
    }

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 50);
}

#[actix_rt::test]
async fn test_treekem_skip_invalid_event() {
    set_env_vars();
    set_env_vars_for_treekem();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();

    let server = Server::new(eid).await.use_treekem().run().await;
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    let init_100_req = init_100_req_fn(&mut csprng, &enc_key, 1, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    // state transition should not be occurred by this transaction.
    logs_clear();
    let transfer_110_req = transfer_110_req_fn(&mut csprng, &enc_key, 2, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_110_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);
    assert!(logs_contain(
        "Error in enclave (InsertCiphertextWorkflow::exec)"
    )); // transfer amount (U64(110)) exceeds balance (U64(100))
    assert!(logs_contain(
        "A event is skipped because of occurring error in enclave"
    ));

    logs_clear();
    let transfer_10_req = transfer_10_req_fn(&mut csprng, &enc_key, 3, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_treekem_node_recovery() {
    set_env_vars();
    set_env_vars_for_treekem();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();

    let server = Server::new(eid).await.use_treekem().run().await;
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    let init_100_req = init_100_req_fn(&mut csprng, &enc_key, 1, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let transfer_10_req_ = transfer_10_req_fn(&mut csprng, &enc_key, 2, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req_)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);

    // Assume the TEE node is down, and then recovered.

    my_turn();

    let recovered_server = Arc::new(Server::new(recovered_eid).await.use_treekem());
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);

    let transfer_10_req = transfer_10_req_fn(&mut csprng, &enc_key, 3, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req)
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 80);
}

#[actix_rt::test]
async fn test_treekem_join_group_then_handshake() {
    set_env_vars();
    set_env_vars_for_treekem();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    // Enclave must be initialized in main function.
    let enclave1 = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid1 = enclave1.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();

    let server1 = Server::new(eid1).await.use_treekem().run().await;
    let server1 = Arc::new(server1);
    let mut app1 = test::init_service(
        App::new()
            .data(server1.clone())
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            ),
    )
    .await;

    actix_rt::time::delay_for(time::Duration::from_millis(2 * SYNC_TIME)).await;

    env::set_var("MY_ROSTER_IDX", "1");
    let enclave2 = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid2 = enclave2.geteid();
    let server2 = Server::new(eid2).await.use_treekem().run().await;
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key1))
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key1))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp); // return 200 OK: because allowed same enclave encryption key

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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    // Requests from party 2
    let init_100_req = init_100_req_fn(&mut csprng, &enc_key, 1, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&init_100_req)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let transfer_10_req = transfer_10_req_fn(&mut csprng, &enc_key, 2, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_10_req)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90);

    env::set_var("ACCOUNT_INDEX", "0");
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_other_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 10);

    // Request from other via state-runtime 1
    let transfer_other_5_req = transfer_other_5_req_fn(&mut csprng, &enc_key, 1, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_other_5_req)
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // check the result of state transition in state-runtime 1
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_other_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 5);

    // check the result of state transition in state-runtime 2
    env::set_var("ACCOUNT_INDEX", "1");
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_other_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 5);

    // Request from other via state-runtime 2
    let transfer_other_5_req = transfer_other_5_req_fn(&mut csprng, &enc_key, 2, None);
    let req = test::TestRequest::post()
        .uri("/api/v1/state")
        .set_json(&transfer_other_5_req)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // check the result of state transition in state-runtime 1
    env::set_var("ACCOUNT_INDEX", "0");
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_other_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);

    // check the result of state transition in state-runtime 2
    env::set_var("ACCOUNT_INDEX", "1");
    let req = test::TestRequest::get()
        .uri("/api/v1/state")
        .set_json(&balance_of_other_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 0);
}

#[actix_rt::test]
async fn test_treekem_duplicated_out_of_order_request_from_same_user() {
    set_env_vars();
    set_env_vars_for_treekem();

    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();

    let server = Server::new(eid).await.use_treekem().run().await;
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
        .set_json(&user_counter_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let user_counter: state_runtime_node_api::user_counter::get::Response =
        test::read_body_json(resp).await;
    assert_eq!(user_counter.user_counter, 0);

    let init_100_req = init_100_req_fn(
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 100);

    let req = test::TestRequest::get()
        .uri("/api/v1/user_counter")
        .set_json(&user_counter_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let user_counter: state_runtime_node_api::user_counter::get::Response =
        test::read_body_json(resp).await;
    assert_eq!(user_counter.user_counter, 1);

    // first request
    let transfer_10 = transfer_10_req_fn(
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90); // success

    let req = test::TestRequest::get()
        .uri("/api/v1/user_counter")
        .set_json(&user_counter_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let user_counter: state_runtime_node_api::user_counter::get::Response =
        test::read_body_json(resp).await;
    assert_eq!(user_counter.user_counter, 2);

    // try second duplicated request
    logs_clear();
    let transfer_10 = transfer_10_req_fn(
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90); // failed
    assert!(logs_contain(
        "Error in enclave (InsertCiphertextWorkflow::exec)"
    )); // InvalidUserCounter
    assert!(logs_contain(
        "A event is skipped because of occurring error in enclave"
    ));

    // send out of order request
    logs_clear();
    let transfer_10 = transfer_10_req_fn(
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 90); // failed
    assert!(logs_contain(
        "Error in enclave (InsertCiphertextWorkflow::exec)"
    )); // InvalidUserCounter
    assert!(logs_contain(
        "A event is skipped because of occurring error in enclave"
    ));

    // then, send correct request
    logs_clear();
    let transfer_10 = transfer_10_req_fn(
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
        .set_json(&balance_of_req_fn(&mut csprng, &enc_key))
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: state_runtime_node_api::state::get::Response = test::read_body_json(resp).await;
    assert_eq!(balance.state, 80); // success
    assert!(!logs_contain("ERROR"));
}
