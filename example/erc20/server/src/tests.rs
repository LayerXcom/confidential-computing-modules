use crate::*;
use actix_web::{test, web, App};
use frame_common::crypto::AccountId;
use frame_runtime::primitives::U64;
use integration_tests::set_env_vars;
use std::time;

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
    let contract_addr: erc20_api::deploy::post::Response = test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_addr);
}

#[actix_rt::test]
async fn test_multiple_messages() {
    set_env_vars();
    set_server_env_vars();

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid));
    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/init_state",
                web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/transfer",
                web::post().to(handle_transfer::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
        .await;

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

    let req = test::TestRequest::post()
        .uri("/api/v1/init_state")
        .set_json(&MINT_100_REQ)
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

    // Sending five messages before receiving any messages
    for _ in 0..5 {
        let req = test::TestRequest::post()
            .uri("/api/v1/transfer")
            .set_json(&TRANSFER_10_REQ)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert!(resp.status().is_success(), "response: {:?}", resp);
    }

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 50);
}

#[actix_rt::test]
async fn test_skip_invalid_event() {
    set_env_vars();
    set_server_env_vars();

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
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
                "/api/v1/init_state",
                web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/transfer",
                web::post().to(handle_transfer::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
        .await;

    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_addr: erc20_api::deploy::post::Response = test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_addr.0);

    let req = test::TestRequest::get()
        .uri("/api/v1/start_sync_bc")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/init_state")
        .set_json(&MINT_100_REQ)
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
        .uri("/api/v1/transfer")
        .set_json(&TRANSFER_110_REQ)
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
        .uri("/api/v1/transfer")
        .set_json(&TRANSFER_10_REQ)
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
    assert_eq!(balance.0.as_raw(), 90);
}

#[actix_rt::test]
async fn test_node_recovery() {
    set_env_vars();
    set_server_env_vars();
    env::remove_var("AUDITOR_ENDPOINT");

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
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
                "/api/v1/init_state",
                web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/transfer",
                web::post().to(handle_transfer::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
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
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_addr",
                web::get().to(handle_set_contract_addr::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/transfer",
                web::post().to(handle_transfer::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
        .await;

    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_addr: erc20_api::deploy::post::Response = test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_addr.0);

    let req = test::TestRequest::get()
        .uri("/api/v1/start_sync_bc")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::post()
        .uri("/api/v1/init_state")
        .set_json(&MINT_100_REQ)
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
        .uri("/api/v1/transfer")
        .set_json(&TRANSFER_10_REQ)
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
    assert_eq!(balance.0.as_raw(), 90);

    // Assume the TEE node is down, and then recovered.

    my_turn();

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_addr")
        .set_json(&erc20_api::contract_addr::post::Request {
            contract_addr: contract_addr.0.clone(),
        })
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 90);

    let req = test::TestRequest::post()
        .uri("/api/v1/transfer")
        .set_json(&TRANSFER_10_REQ)
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut recovered_app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 80);
}

#[actix_rt::test]
async fn test_join_group_then_handshake() {
    set_env_vars();
    set_server_env_vars();

    // Enclave must be initialized in main function.
    let enclave1 = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid1 = enclave1.geteid();
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
                "/api/v1/init_state",
                web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/transfer",
                web::post().to(handle_transfer::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_addr",
                web::get().to(handle_set_contract_addr::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/key_rotation",
                web::post().to(handle_key_rotation::<EthDeployer, EthSender, EventWatcher>),
            ),
    )
        .await;

    // Party 1

    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let contract_addr: erc20_api::deploy::post::Response = test::read_body_json(resp).await;
    println!("contract address: {:?}", contract_addr.0);

    let req = test::TestRequest::get()
        .uri("/api/v1/start_sync_bc")
        .to_request();
    let resp = test::call_service(&mut app1, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // Party 2

    other_turn();

    let req = test::TestRequest::get()
        .uri("/api/v1/set_contract_addr")
        .set_json(&erc20_api::contract_addr::post::Request {
            contract_addr: contract_addr.0.clone(),
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
        .set_json(&erc20_api::join_group::post::Request {
            contract_addr: contract_addr.0,
        })
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/init_state")
        .set_json(&MINT_100_REQ)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 100);

    let req = test::TestRequest::post()
        .uri("/api/v1/key_rotation")
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    actix_rt::time::delay_for(time::Duration::from_millis(SYNC_TIME)).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/transfer")
        .set_json(&TRANSFER_10_REQ)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    let req = test::TestRequest::get()
        .uri("/api/v1/balance_of")
        .set_json(&BALANCE_OF_REQ)
        .to_request();
    let resp = test::call_service(&mut app2, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);
    let balance: erc20_api::state::get::Response<U64> = test::read_body_json(resp).await;
    assert_eq!(balance.0.as_raw(), 90);
}

fn set_server_env_vars() {
    env::set_var("ETH_URL", "http://172.28.0.2:8545");
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

// to me
const MINT_100_REQ: erc20_api::init_state::post::Request = erc20_api::init_state::post::Request {
    sig: [
        236, 103, 17, 252, 166, 199, 9, 46, 200, 107, 188, 0, 37, 111, 83, 105, 175, 81, 231, 14,
        81, 100, 221, 89, 102, 172, 30, 96, 15, 128, 117, 146, 181, 221, 149, 206, 163, 208, 113,
        198, 241, 16, 150, 248, 99, 170, 85, 122, 165, 197, 14, 120, 110, 37, 69, 32, 36, 218, 100,
        64, 224, 226, 99, 2,
    ],
    pubkey: [
        164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33, 189,
        55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
    ],
    challenge: [
        244, 158, 183, 202, 237, 236, 27, 67, 39, 95, 178, 136, 235, 162, 188, 106, 52, 56, 6, 245,
        3, 101, 33, 155, 58, 175, 168, 63, 73, 125, 205, 225,
    ],
    total_supply: 100,
};

// from me to other
const TRANSFER_10_REQ: erc20_api::transfer::post::Request = erc20_api::transfer::post::Request {
    sig: [
        227, 77, 52, 167, 149, 64, 24, 23, 103, 227, 13, 120, 90, 186, 1, 62, 110, 60, 186, 247,
        143, 247, 19, 71, 85, 191, 224, 5, 38, 219, 96, 44, 196, 154, 181, 50, 99, 58, 20, 125,
        244, 172, 212, 166, 234, 203, 208, 77, 9, 232, 77, 248, 152, 81, 106, 49, 120, 34, 212, 89,
        92, 100, 221, 14,
    ],
    pubkey: [
        164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33, 189,
        55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
    ],
    challenge: [
        157, 61, 16, 189, 40, 124, 88, 101, 19, 36, 155, 229, 245, 123, 189, 124, 222, 114, 215,
        186, 25, 30, 135, 114, 237, 169, 138, 122, 81, 61, 43, 183,
    ],
    target: AccountId([
        236, 126, 92, 200, 50, 125, 9, 112, 74, 58, 35, 60, 181, 105, 198, 107, 62, 111, 168, 118,
    ]),
    amount: 10,
};

// from me to other
const TRANSFER_110_REQ: erc20_api::transfer::post::Request = erc20_api::transfer::post::Request {
    sig: [
        227, 77, 52, 167, 149, 64, 24, 23, 103, 227, 13, 120, 90, 186, 1, 62, 110, 60, 186, 247,
        143, 247, 19, 71, 85, 191, 224, 5, 38, 219, 96, 44, 196, 154, 181, 50, 99, 58, 20, 125,
        244, 172, 212, 166, 234, 203, 208, 77, 9, 232, 77, 248, 152, 81, 106, 49, 120, 34, 212, 89,
        92, 100, 221, 14,
    ],
    pubkey: [
        164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33, 189,
        55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
    ],
    challenge: [
        157, 61, 16, 189, 40, 124, 88, 101, 19, 36, 155, 229, 245, 123, 189, 124, 222, 114, 215,
        186, 25, 30, 135, 114, 237, 169, 138, 122, 81, 61, 43, 183,
    ],
    target: AccountId([
        236, 126, 92, 200, 50, 125, 9, 112, 74, 58, 35, 60, 181, 105, 198, 107, 62, 111, 168, 118,
    ]),
    amount: 110,
};

// me
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
