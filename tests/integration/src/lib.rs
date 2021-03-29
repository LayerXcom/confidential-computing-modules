#[macro_use]
extern crate lazy_static;
use anonify_ecall_types::cmd::*;
use anonify_eth_driver::{dispatcher::*, eth::*, EventCache};
use eth_deployer::EthDeployer;
use ethabi::Contract as ContractABI;
use frame_common::{
    crypto::{AccountId, Ed25519ChallengeResponse, COMMON_ACCESS_POLICY},
    state_types::NotifyState,
    traits::*,
};
use frame_config::{ANONIFY_ABI_PATH, ANONIFY_BIN_PATH, FACTORY_ABI_PATH, FACTORY_BIN_PATH};
use frame_host::EnclaveDir;
use frame_runtime::primitives::{Approved, U64};
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use once_cell::sync::Lazy;
use serde_json::json;
use sgx_types::*;
use std::{collections::BTreeMap, env, fs::File, io::BufReader, str::FromStr};
use web3::{
    contract::{Contract, Options},
    transports::Http,
    types::Address,
    Web3,
};

const ACCOUNT_INDEX: usize = 0;
const PASSWORD: &str = "anonify0101";
const CONFIRMATIONS: usize = 0;

pub static ETH_URL: Lazy<String> =
    Lazy::new(|| env::var("ETH_URL").unwrap_or("http://172.16.0.2:8545".to_string()));

pub async fn get_enclave_encryption_key(
    contract_addr: Address,
    dispatcher: &Dispatcher,
) -> SodiumPubKey {
    let enclave_encryption_key = dispatcher.get_enclave_encryption_key().unwrap();
    let transport = Http::new(&*ETH_URL).unwrap();
    let web3 = Web3::new(transport);
    let web3_conn = web3.eth();

    let f = File::open(&*ANONIFY_ABI_PATH).unwrap();
    let abi = ContractABI::load(BufReader::new(f)).unwrap();

    let query_enclave_encryption_key: Vec<u8> = Contract::new(web3_conn, contract_addr, abi)
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

#[actix_rt::test]
async fn test_integration_eth_construct() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();

    // Deploy
    let deployer = EthDeployer::new(&*ETH_URL).unwrap();
    let deployer_addr = deployer
        .get_account(ACCOUNT_INDEX, Some(PASSWORD))
        .await
        .unwrap();
    let factory_contract_addr = deployer
        .deploy(
            &*FACTORY_ABI_PATH,
            &*FACTORY_BIN_PATH,
            CONFIRMATIONS,
            gas,
            deployer_addr.clone(),
        )
        .await
        .unwrap();
    let tx_hash = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithTreeKem",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();

    let dispatcher = Dispatcher::new(eid, &*ETH_URL, CONFIRMATIONS, cache)
        .set_anonify_contract_address(
            &*FACTORY_ABI_PATH,
            factory_contract_addr,
            &*ANONIFY_ABI_PATH,
        )
        .await
        .unwrap();
    let anonify_contract_addr = dispatcher.get_anonify_contract_address().unwrap();

    println!("Deployer account_id: {:?}", deployer_addr);
    println!("factory contract address: {}", factory_contract_addr);
    println!("anonify contract address: {}", anonify_contract_addr);

    dispatcher
        .join_group(deployer_addr, gas, JOIN_GROUP_TREEKEM_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply: u64 = 100;
    let pubkey = get_enclave_encryption_key(anonify_contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "owner",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    // Get state from enclave
    let owner_account_id = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "total_supply",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let actual_total_supply = dispatcher.get_state(encrypted_req).unwrap();
    println!("owner_account_id: {:?}", owner_account_id);
    assert_eq!(
        owner_account_id,
        serde_json::to_value(my_access_policy.into_account_id()).unwrap()
    );
    assert_eq!(my_balance, total_supply);
    assert_eq!(actual_total_supply, total_supply);
}

#[actix_rt::test]
async fn test_auto_notification() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();

    // Deploy
    let deployer = EthDeployer::new(&*ETH_URL).unwrap();
    let deployer_addr = deployer
        .get_account(ACCOUNT_INDEX, Some(PASSWORD))
        .await
        .unwrap();
    let factory_contract_addr = deployer
        .deploy(
            &*FACTORY_ABI_PATH,
            &*FACTORY_BIN_PATH,
            CONFIRMATIONS,
            gas,
            deployer_addr.clone(),
        )
        .await
        .unwrap();
    let tx_hash = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithTreeKem",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();

    let dispatcher = Dispatcher::new(eid, &*ETH_URL, CONFIRMATIONS, cache)
        .set_anonify_contract_address(
            &*FACTORY_ABI_PATH,
            factory_contract_addr,
            &*ANONIFY_ABI_PATH,
        )
        .await
        .unwrap();
    let anonify_contract_addr = dispatcher.get_anonify_contract_address().unwrap();

    println!("Deployer account_id: {:?}", deployer_addr);
    println!("factory contract address: {}", factory_contract_addr);
    println!("anonify contract address: {}", anonify_contract_addr);

    dispatcher
        .join_group(deployer_addr, gas, JOIN_GROUP_TREEKEM_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Init state
    let pubkey = get_enclave_encryption_key(anonify_contract_addr, &dispatcher).await;
    let total_supply: u64 = 100;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();

    let req = json!({
        "access_policy": my_access_policy.clone(),
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    dispatcher.register_notification(encrypted_req).unwrap();

    // Get logs from contract and update state inside enclave.
    let updated_state = dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap()
        .unwrap();
    let notified_state: Vec<NotifyState> = updated_state
        .into_iter()
        .map(|e| serde_json::from_value(e).unwrap())
        .collect();

    assert_eq!(notified_state.len(), 1);
    assert_eq!(
        notified_state[0].account_id,
        my_access_policy.into_account_id()
    );
    assert_eq!(notified_state[0].mem_id.as_raw(), 0);
    assert_eq!(
        serde_json::from_value::<U64>(notified_state[0].state.clone()).unwrap(),
        U64::from_raw(total_supply)
    );

    // Send a transaction to contract
    let amount: u64 = 30;
    let recipient = other_access_policy.into_account_id();
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "amount": amount,
            "recipient": recipient,
        },
        "cmd_name": "transfer",
        "counter": 2,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    let updated_state = dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap()
        .unwrap();
    let notified_state: Vec<NotifyState> = updated_state
        .into_iter()
        .map(|e| serde_json::from_value(e).unwrap())
        .collect();

    assert_eq!(notified_state.len(), 1);
    assert_eq!(
        notified_state[0].account_id,
        my_access_policy.into_account_id()
    );
    assert_eq!(notified_state[0].mem_id.as_raw(), 0);
    assert_eq!(
        serde_json::from_value::<U64>(notified_state[0].state.clone()).unwrap(),
        U64::from_raw(70)
    );
}

#[actix_rt::test]
async fn test_integration_eth_transfer() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let third_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();

    // Deploy
    let deployer = EthDeployer::new(&*ETH_URL).unwrap();
    let deployer_addr = deployer
        .get_account(ACCOUNT_INDEX, Some(PASSWORD))
        .await
        .unwrap();
    let factory_contract_addr = deployer
        .deploy(
            &*FACTORY_ABI_PATH,
            &*FACTORY_BIN_PATH,
            CONFIRMATIONS,
            gas,
            deployer_addr.clone(),
        )
        .await
        .unwrap();
    let tx_hash = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithTreeKem",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();

    let dispatcher = Dispatcher::new(eid, &*ETH_URL, CONFIRMATIONS, cache)
        .set_anonify_contract_address(
            &*FACTORY_ABI_PATH,
            factory_contract_addr,
            &*ANONIFY_ABI_PATH,
        )
        .await
        .unwrap();
    let anonify_contract_addr = dispatcher.get_anonify_contract_address().unwrap();

    println!("Deployer account_id: {:?}", deployer_addr);
    println!("factory contract address: {}", factory_contract_addr);
    println!("anonify contract address: {}", anonify_contract_addr);

    dispatcher
        .join_group(deployer_addr, gas, JOIN_GROUP_TREEKEM_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply: u64 = 100;
    let pubkey = get_enclave_encryption_key(anonify_contract_addr, &dispatcher).await;

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Get state from enclave
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(my_state, total_supply);
    assert_eq!(other_state, 0);
    assert_eq!(third_state, 0);

    // Send a transaction to contract
    let amount: u64 = 30;
    let recipient = other_access_policy.into_account_id();
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "amount": amount,
            "recipient": recipient,
        },
        "cmd_name": "transfer",
        "counter": 2,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Check the updated states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_updated_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_updated_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let third_updated_state = dispatcher.get_state(encrypted_req).unwrap();

    assert_eq!(my_updated_state, 70);
    assert_eq!(other_updated_state, amount);
    assert_eq!(third_updated_state, 0);
}

#[actix_rt::test]
async fn test_key_rotation() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let third_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();

    // Deploy
    let deployer = EthDeployer::new(&*ETH_URL).unwrap();
    let deployer_addr = deployer
        .get_account(ACCOUNT_INDEX, Some(PASSWORD))
        .await
        .unwrap();
    let factory_contract_addr = deployer
        .deploy(
            &*FACTORY_ABI_PATH,
            &*FACTORY_BIN_PATH,
            CONFIRMATIONS,
            gas,
            deployer_addr.clone(),
        )
        .await
        .unwrap();
    let tx_hash = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithTreeKem",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();

    let dispatcher = Dispatcher::new(eid, &*ETH_URL, CONFIRMATIONS, cache)
        .set_anonify_contract_address(
            &*FACTORY_ABI_PATH,
            factory_contract_addr,
            &*ANONIFY_ABI_PATH,
        )
        .await
        .unwrap();
    let anonify_contract_addr = dispatcher.get_anonify_contract_address().unwrap();

    println!("Deployer account_id: {:?}", deployer_addr);
    println!("factory contract address: {}", factory_contract_addr);
    println!("anonify contract address: {}", anonify_contract_addr);

    dispatcher
        .join_group(deployer_addr, gas, JOIN_GROUP_TREEKEM_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Send handshake
    let receipt = dispatcher
        .handshake(deployer_addr.clone(), gas)
        .await
        .unwrap();
    println!("handshake receipt: {:?}", receipt);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // init state
    let total_supply: u64 = 100;
    let pubkey = get_enclave_encryption_key(anonify_contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();
    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Get state from enclave
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(my_state, total_supply);
    assert_eq!(other_state, 0);
    assert_eq!(third_state, 0);
}

#[actix_rt::test]
async fn test_integration_eth_approve() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();

    // Deploy
    let deployer = EthDeployer::new(&*ETH_URL).unwrap();
    let deployer_addr = deployer
        .get_account(ACCOUNT_INDEX, Some(PASSWORD))
        .await
        .unwrap();
    let factory_contract_addr = deployer
        .deploy(
            &*FACTORY_ABI_PATH,
            &*FACTORY_BIN_PATH,
            CONFIRMATIONS,
            gas,
            deployer_addr.clone(),
        )
        .await
        .unwrap();
    let tx_hash = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithTreeKem",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();

    let dispatcher = Dispatcher::new(eid, &*ETH_URL, CONFIRMATIONS, cache)
        .set_anonify_contract_address(
            &*FACTORY_ABI_PATH,
            factory_contract_addr,
            &*ANONIFY_ABI_PATH,
        )
        .await
        .unwrap();
    let anonify_contract_addr = dispatcher.get_anonify_contract_address().unwrap();

    println!("Deployer account_id: {:?}", deployer_addr);
    println!("factory contract address: {}", factory_contract_addr);
    println!("anonify contract address: {}", anonify_contract_addr);

    dispatcher
        .join_group(deployer_addr, gas, JOIN_GROUP_TREEKEM_CMD)
        .await
        .unwrap();
    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply = 100;
    let pubkey = get_enclave_encryption_key(anonify_contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    let spender = other_access_policy.into_account_id();
    // Get state from enclave
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(my_state, 0);
    assert_eq!(other_state, 0);

    // Send a transaction to contract
    let amount: u64 = 30;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "amount": amount,
            "spender": spender,
        },
        "cmd_name": "approve",
        "counter": 2,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Check the updated states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state = dispatcher.get_state(encrypted_req).unwrap();

    assert_eq!(my_state, amount);
    assert_eq!(other_state, 0);
}

#[actix_rt::test]
async fn test_integration_eth_transfer_from() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let third_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();

    // Deploy
    let deployer = EthDeployer::new(&*ETH_URL).unwrap();
    let deployer_addr = deployer
        .get_account(ACCOUNT_INDEX, Some(PASSWORD))
        .await
        .unwrap();
    let factory_contract_addr = deployer
        .deploy(
            &*FACTORY_ABI_PATH,
            &*FACTORY_BIN_PATH,
            CONFIRMATIONS,
            gas,
            deployer_addr.clone(),
        )
        .await
        .unwrap();
    let tx_hash = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithTreeKem",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();

    let dispatcher = Dispatcher::new(eid, &*ETH_URL, CONFIRMATIONS, cache)
        .set_anonify_contract_address(
            &*FACTORY_ABI_PATH,
            factory_contract_addr,
            &*ANONIFY_ABI_PATH,
        )
        .await
        .unwrap();
    let anonify_contract_addr = dispatcher.get_anonify_contract_address().unwrap();

    println!("Deployer account_id: {:?}", deployer_addr);
    println!("factory contract address: {}", factory_contract_addr);
    println!("anonify contract address: {}", anonify_contract_addr);

    dispatcher
        .join_group(deployer_addr, gas, JOIN_GROUP_TREEKEM_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply: u64 = 100;
    let pubkey = get_enclave_encryption_key(anonify_contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Get initial state from enclave
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_balance = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(my_state_balance, 100);
    assert_eq!(other_state_balance, 0);
    assert_eq!(third_state_balance, 0);

    let spender = other_access_policy.into_account_id();
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_approved = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(my_state_approved, 0);
    assert_eq!(other_state_approved, 0);
    assert_eq!(third_state_approved, 0);

    // Send a transaction to contract
    let amount: u64 = 30;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "amount": amount,
            "spender": spender,
        },
        "cmd_name": "approve",
        "counter": 2,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Check the updated states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_balance = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(my_state_balance, 100);
    assert_eq!(other_state_balance, 0);
    assert_eq!(third_state_balance, 0);

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    assert_eq!(my_state_approved, amount);
    assert_eq!(other_state_approved, 0);
    assert_eq!(third_state_approved, 0);

    // Send a transaction to contract
    let amount: u64 = 20;
    let owner = my_access_policy.into_account_id();
    let recipient = third_access_policy.into_account_id();
    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "owner": owner,
            "recipient": recipient,
            "amount": amount,
        },
        "cmd_name": "transfer_from",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Check the final states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_balance = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(my_state_balance, 80);
    assert_eq!(other_state_balance, 0);
    assert_eq!(third_state_balance, 20);

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    assert_eq!(my_state_approved, 10);
    assert_eq!(other_state_approved, 0);
    assert_eq!(third_state_approved, 0);
}

#[actix_rt::test]
async fn test_integration_eth_mint() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();

    // Deploy
    let deployer = EthDeployer::new(&*ETH_URL).unwrap();
    let deployer_addr = deployer
        .get_account(ACCOUNT_INDEX, Some(PASSWORD))
        .await
        .unwrap();
    let factory_contract_addr = deployer
        .deploy(
            &*FACTORY_ABI_PATH,
            &*FACTORY_BIN_PATH,
            CONFIRMATIONS,
            gas,
            deployer_addr.clone(),
        )
        .await
        .unwrap();
    let tx_hash = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithTreeKem",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();

    let dispatcher = Dispatcher::new(eid, &*ETH_URL, CONFIRMATIONS, cache)
        .set_anonify_contract_address(
            &*FACTORY_ABI_PATH,
            factory_contract_addr,
            &*ANONIFY_ABI_PATH,
        )
        .await
        .unwrap();
    let anonify_contract_addr = dispatcher.get_anonify_contract_address().unwrap();

    println!("Deployer account_id: {:?}", deployer_addr);
    println!("factory contract address: {}", factory_contract_addr);
    println!("anonify contract address: {}", anonify_contract_addr);

    dispatcher
        .join_group(deployer_addr, gas, JOIN_GROUP_TREEKEM_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply = 100;
    let pubkey = get_enclave_encryption_key(anonify_contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // transit state
    let amount = 50;
    let recipient = other_access_policy.into_account_id();
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "amount": amount,
            "recipient": recipient,
        },
        "cmd_name": "mint",
        "counter": 2,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();

    println!("minted state receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "total_supply",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    // Check the final states
    let actual_total_supply = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let owner_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_balance = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(actual_total_supply, 150);
    assert_eq!(owner_balance, 100);
    assert_eq!(other_balance, amount);
}

#[actix_rt::test]
async fn test_integration_eth_burn() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    // just for testing
    let mut csprng = rand::thread_rng();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();

    // Deploy
    let deployer = EthDeployer::new(&*ETH_URL).unwrap();
    let deployer_addr = deployer
        .get_account(ACCOUNT_INDEX, Some(PASSWORD))
        .await
        .unwrap();
    let factory_contract_addr = deployer
        .deploy(
            &*FACTORY_ABI_PATH,
            &*FACTORY_BIN_PATH,
            CONFIRMATIONS,
            gas,
            deployer_addr.clone(),
        )
        .await
        .unwrap();
    let tx_hash = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithTreeKem",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();

    let dispatcher = Dispatcher::new(eid, &*ETH_URL, CONFIRMATIONS, cache)
        .set_anonify_contract_address(
            &*FACTORY_ABI_PATH,
            factory_contract_addr,
            &*ANONIFY_ABI_PATH,
        )
        .await
        .unwrap();
    let anonify_contract_addr = dispatcher.get_anonify_contract_address().unwrap();

    println!("Deployer account_id: {:?}", deployer_addr);
    println!("factory contract address: {}", factory_contract_addr);
    println!("anonify contract address: {}", anonify_contract_addr);

    dispatcher
        .join_group(deployer_addr, gas, JOIN_GROUP_TREEKEM_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply = 100;
    let pubkey = get_enclave_encryption_key(anonify_contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Send a transaction to contract
    let amount = 30;
    let recipient = other_access_policy.into_account_id();
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "amount": amount,
            "recipient": recipient,
        },
        "cmd_name": "transfer",
        "counter": 2,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    // Send a transaction to contract
    let amount = 20;
    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "amount": amount,
        },
        "cmd_name": "burn",
        "counter": 1,
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_TREEKEM_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_TREEKEM_CMD, FETCH_HANDSHAKE_TREEKEM_CMD)
        .await
        .unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "total_supply",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    // Check the final states
    let actual_total_supply = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": my_access_policy,
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let owner_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy,
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap()).unwrap();
    let other_balance = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(actual_total_supply.as_u64().unwrap(), 80); // 100 - 20(burn)
    assert_eq!(owner_balance, 70); // 100 - 30(transfer)
    assert_eq!(other_balance, 10); // 30 - 20(burn)
}

lazy_static! {
    pub static ref ENV_LOGGER_INIT: () = tracing_subscriber::fmt::init();
}

pub fn set_env_vars() {
    lazy_static::initialize(&ENV_LOGGER_INIT);
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    env::set_var(
        "IAS_URL",
        "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report",
    );
    env::set_var("ENCLAVE_PKG_NAME", "erc20");
    env::set_var("BACKUP", "disable");
}
