#[macro_use]
extern crate lazy_static;
use anonify_eth_driver::{dispatcher::*, eth::*, EventCache};
use anonify_ecall_types::cmd::*;
use ethabi::Contract as ContractABI;
use frame_common::{
    crypto::{AccountId, Ed25519ChallengeResponse, COMMON_ACCESS_POLICY},
    state_types::NotifyState,
    traits::*,
};
use frame_host::EnclaveDir;
use frame_runtime::primitives::{Approved, U64};
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use serde_json::json;
use sgx_types::*;
use std::{collections::BTreeMap, env, fs::File, io::BufReader, str::FromStr};
use web3::{
    contract::{Contract, Options},
    transports::Http,
    types::Address,
    Web3,
};

const ETH_URL: &str = "http://172.28.0.2:8545";
const ABI_PATH: &str = "../../contract-build/Anonify.abi";
const BIN_PATH: &str = "../../contract-build/Anonify.bin";
const CONFIRMATIONS: usize = 0;
const ACCOUNT_INDEX: usize = 0;
const PASSWORD: &str = "anonify0101";

pub async fn get_enclave_encryption_key(
    contract_addr: &str,
    dispatcher: &Dispatcher<EthDeployer, EthSender, EventWatcher>,
) -> SodiumPubKey {
    let enclave_encryption_key = dispatcher
        .get_enclave_encryption_key(GET_ENCLAVE_ENCRYPTION_KEY_CMD)
        .unwrap();
    let transport = Http::new(ETH_URL).unwrap();
    let web3 = Web3::new(transport);
    let web3_conn = web3.eth();

    let address = Address::from_str(contract_addr).unwrap();
    let f = File::open(ABI_PATH).unwrap();
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
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

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
            JOIN_GROUP_CMD,
        )
        .await
        .unwrap();
    dispatcher
        .set_contract_address(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply: u64 = 100;
    let pubkey = get_enclave_encryption_key(&contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "owner",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    // Get state from enclave
    let owner_account_id = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "total_supply",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let actual_total_supply = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

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
            JOIN_GROUP_CMD,
        )
        .await
        .unwrap();
    dispatcher
        .set_contract_address(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Init state
    let pubkey = get_enclave_encryption_key(&contract_addr, &dispatcher).await;
    let total_supply: u64 = 100;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();

    let req = json!({
        "access_policy": my_access_policy.clone(),
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    dispatcher
        .register_notification(encrypted_req, REGISTER_NOTIFICATION_CMD)
        .unwrap();

    // Get logs from contract and update state inside enclave.
    let updated_state = dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
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
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(encrypted_command, deployer_addr, gas, SEND_COMMAND_CMD)
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    let updated_state = dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
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
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

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
            JOIN_GROUP_CMD,
        )
        .await
        .unwrap();
    dispatcher
        .set_contract_address(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply: u64 = 100;
    let pubkey = get_enclave_encryption_key(&contract_addr, &dispatcher).await;

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Get state from enclave
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(encrypted_command, deployer_addr, gas, SEND_COMMAND_CMD)
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Check the updated states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_updated_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_updated_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let third_updated_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

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
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

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
            JOIN_GROUP_CMD,
        )
        .await
        .unwrap();
    dispatcher
        .set_contract_address(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Send handshake
    let receipt = dispatcher
        .handshake(deployer_addr.clone(), gas, SEND_HANDSHAKE_CMD)
        .await
        .unwrap();
    println!("handshake receipt: {:?}", receipt);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // init state
    let total_supply: u64 = 100;
    let pubkey = get_enclave_encryption_key(&contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();
    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Get state from enclave
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

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
            JOIN_GROUP_CMD,
        )
        .await
        .unwrap();
    dispatcher
        .set_contract_address(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply = 100;
    let pubkey = get_enclave_encryption_key(&contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(encrypted_command, deployer_addr, gas, SEND_COMMAND_CMD)
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

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
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

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
            JOIN_GROUP_CMD,
        )
        .await
        .unwrap();
    dispatcher
        .set_contract_address(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply: u64 = 100;
    let pubkey = get_enclave_encryption_key(&contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Get initial state from enclave
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_approved = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_approved = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_approved = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Check the updated states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_approved = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_approved = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_approved = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

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
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(encrypted_command, deployer_addr, gas, SEND_COMMAND_CMD)
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Check the final states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let my_state_approved = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_state_approved = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let third_state_approved = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

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
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

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
            JOIN_GROUP_CMD,
        )
        .await
        .unwrap();
    dispatcher
        .set_contract_address(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply = 100;
    let pubkey = get_enclave_encryption_key(&contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
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
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(encrypted_command, deployer_addr, gas, SEND_COMMAND_CMD)
        .await
        .unwrap();

    println!("minted state receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "total_supply",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    // Check the final states
    let actual_total_supply = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let owner_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

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
            JOIN_GROUP_CMD,
        )
        .await
        .unwrap();
    dispatcher
        .set_contract_address(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    // Init state
    let total_supply = 100;
    let pubkey = get_enclave_encryption_key(&contract_addr, &dispatcher).await;
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
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
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
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
    });
    let encrypted_command =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let receipt = dispatcher
        .send_command(encrypted_command, deployer_addr, gas, SEND_COMMAND_CMD)
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "total_supply",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    // Check the final states
    let actual_total_supply = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": my_access_policy,
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let owner_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();

    let req = json!({
        "access_policy": other_access_policy,
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, serde_json::to_vec(&req).unwrap()).unwrap();
    let other_balance = dispatcher.get_state(encrypted_req, GET_STATE_CMD).unwrap();
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
    env::set_var("KEY_VAULT_ENDPOINT", "localhost:12345");
    env::set_var("AUDITOR_ENDPOINT", "test");
    env::set_var("ENCLAVE_PKG_NAME", "erc20");
    env::set_var("BACKUP", "disable");
}
