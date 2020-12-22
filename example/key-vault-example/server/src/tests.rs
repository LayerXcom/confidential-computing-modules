use crate::*;

use actix_web::{test, web, App};
use anonify_eth_driver::{
    dispatcher::Dispatcher as EthDispatcher,
    eth::{EthDeployer, EthSender, EventWatcher},
    EventCache,
};
use frame_common::crypto::Ed25519ChallengeResponse;
use frame_runtime::primitives::U64;
use frame_treekem::EciesCiphertext;
use integration_tests::{set_env_vars, get_encrypting_key};
use erc20_state_transition::{construct, CallName, MemName, CIPHERTEXT_SIZE};

const ETH_URL: &str = "http://172.28.0.2:8545";
const ABI_PATH: &str = "../../contract-build/Anonify.abi";
const BIN_PATH: &str = "../../contract-build/Anonify.bin";
const CONFIRMATIONS: usize = 0;
const ACCOUNT_INDEX: usize = 0;
const PASSWORD: &str = "anonify0101";

#[actix_rt::test]
async fn test_backup_path_secret() {
    set_env_vars();

    // Setup backup server
    let server_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let server_eid = server_enclave.geteid();
    let server = Arc::new(Server::new(server_eid));

    let mut app = test::init_service(
        App::new()
            .data(server.clone())
            .route("/api/v1/start", web::post().to(handle_start))
            .route("/api/v1/stop", web::post().to(handle_stop)),
    )
    .await;

    let req = test::TestRequest::post().uri("/api/v1/start").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "response: {:?}", resp);

    // Setup ERC20 application
    let app_enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let app_eid = app_enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();
    let dispatcher =
        EthDispatcher::<EthDeployer, EthSender, EventWatcher>::new(app_eid, ETH_URL, cache).unwrap();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
    let (contract_addr, export_path_secret) = dispatcher
        .deploy(
            deployer_addr.clone(),
            gas,
            ABI_PATH,
            BIN_PATH,
            CONFIRMATIONS,
        )
        .await
        .unwrap();
    dispatcher
        .set_contract_addr(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);
    println!("export_path_secret: {:?}", export_path_secret);

    // Get handshake from contract
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let pubkey = get_encrypting_key(&contract_addr, &dispatcher).await;
    let init_cmd = construct { total_supply };
    let encrypted_command = EciesCiphertext::encrypt(&pubkey, init_cmd.encode()).unwrap();
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);
}
