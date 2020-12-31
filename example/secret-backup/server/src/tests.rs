use crate::*;
use actix_web::{test, web, App};
use anonify_config::{LOCAL_PATH_SECRETS_DIR, PJ_ROOT_DIR};
use anonify_eth_driver::{
    dispatcher::Dispatcher as EthDispatcher,
    eth::{EthDeployer, EthSender, EventWatcher},
    EventCache,
};
use codec::{Decode, Encode};
use erc20_state_transition::{construct, CallName};
use ethabi::Contract as ContractABI;
use frame_common::crypto::Ed25519ChallengeResponse;
use frame_runtime::primitives::U64;
use frame_treekem::{DhPubKey, EciesCiphertext};
use once_cell::sync::Lazy;
use std::{
    env,
    fs::{self, File},
    io::BufReader,
    path::Path,
    str::FromStr,
};
use web3::{
    contract::{Contract, Options},
    transports::Http,
    types::Address,
    Web3,
};

const ETH_URL: &str = "http://172.28.0.2:8545";
const ABI_PATH: &str = "../../../contract-build/Anonify.abi";
const BIN_PATH: &str = "../../../contract-build/Anonify.bin";
const CONFIRMATIONS: usize = 0;
const ACCOUNT_INDEX: usize = 0;
const PASSWORD: &str = "anonify0101";

pub async fn get_encrypting_key(
    contract_addr: &str,
    dispatcher: &EthDispatcher<EthDeployer, EthSender, EventWatcher>,
) -> DhPubKey {
    let encrypting_key = dispatcher.get_encrypting_key().unwrap();
    let transport = Http::new(ETH_URL).unwrap();
    let web3 = Web3::new(transport);
    let web3_conn = web3.eth();

    let address = Address::from_str(contract_addr).unwrap();
    let f = File::open(ABI_PATH).unwrap();
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

#[actix_rt::test]
async fn test_backup_path_secret() {
    set_env_vars();
    clear_path_secrets();

    // Setup backup server
    let server_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize server enclave.");
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
    let start_response: secret_backup_api::start::post::Response = test::read_body_json(resp).await;
    assert_eq!(start_response.status, "success".to_string());

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Setup ERC20 application
    env::set_var("ENCLAVE_PKG_NAME", "erc20");
    let app_enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize client enclave.");
    let app_eid = app_enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();
    let dispatcher =
        EthDispatcher::<EthDeployer, EthSender, EventWatcher>::new(app_eid, ETH_URL, cache)
            .unwrap();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
    let contract_addr = dispatcher
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

    let path_secrets_dir = PJ_ROOT_DIR.join(LOCAL_PATH_SECRETS_DIR);

    let id = get_path_secret_id().unwrap();
    // local
    assert!(path_secrets_dir.join(&id).exists());
    // remote
    assert!(path_secrets_dir
        .join(env::var("MY_ROSTER_IDX").unwrap().as_str())
        .join(&id)
        .exists());

    delete_local_path_secret(id);

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

pub static ENV_LOGGER_INIT: Lazy<()> = Lazy::new(|| {
    env_logger::init();
});

fn set_env_vars() {
    *ENV_LOGGER_INIT;
    env::set_var("RUST_LOG", "DEBUG");
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    env::set_var("SPID", "2C149BFC94A61D306A96211AED155BE9");
    env::set_var(
        "IAS_URL",
        "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report",
    );
    env::set_var("SUB_KEY", "77e2533de0624df28dc3be3a5b9e50d9");
    env::set_var("MRA_TLS_SERVER_ADDRESS", "localhost:12345");
    env::set_var("AUDITOR_ENDPOINT", "test");
    env::set_var("ENCLAVE_PKG_NAME", "secret_backup");
}

fn delete_local_path_secret(id: String) {
    let target = PJ_ROOT_DIR.join(LOCAL_PATH_SECRETS_DIR).join(id);
    if target.exists() {
        fs::remove_file(target).unwrap();
    }
}

fn clear_path_secrets() {
    let target = PJ_ROOT_DIR.join(LOCAL_PATH_SECRETS_DIR);
    if target.exists() {
        fs::remove_dir_all(target).unwrap();
    }
}

fn get_path_secret_id() -> Option<String> {
    for path in fs::read_dir(PJ_ROOT_DIR.join(LOCAL_PATH_SECRETS_DIR)).unwrap() {
        if path.as_ref().unwrap().file_type().unwrap().is_dir() {
            continue;
        }
        return Some(path.unwrap().file_name().into_string().unwrap());
    }

    None
}
