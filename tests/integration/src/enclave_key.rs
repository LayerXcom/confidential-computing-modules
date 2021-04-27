#![cfg(test)]
use anonify_ecall_types::cmd::*;
use anonify_eth_driver::dispatcher::*;
use anonify_eth_driver::EventCache;
use eth_deployer::EthDeployer;
use frame_common::{
    crypto::{Ed25519ChallengeResponse, COMMON_ACCESS_POLICY},
    state_types::NotifyState,
    traits::*,
};
use frame_config::ANONIFY_ABI_PATH;
use frame_config::{FACTORY_ABI_PATH, FACTORY_BIN_PATH};
use frame_host::EnclaveDir;
use frame_runtime::primitives::U64;
use frame_sodium::SodiumCiphertext;
use serde_json::json;
#[cfg(test)]
use test_utils::tracing::logs_contain;

use crate::{
    get_enclave_encryption_key, set_env_vars, ACCOUNT_INDEX, CONFIRMATIONS, ETH_URL, PASSWORD,
};

#[actix_rt::test]
pub async fn test_enclave_key_integration_eth_construct() {
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
    let receipt = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithEnclaveKey",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();
    println!("deployed receipt: {:?}", receipt);

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
        .join_group(deployer_addr, gas, JOIN_GROUP_ENCLAVE_KEY_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
        .await
        .unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "owner",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    // Get state from enclave
    let owner_account_id = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "total_supply",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let actual_total_supply = dispatcher.get_state(encrypted_req).unwrap();
    println!("owner_account_id: {:?}", owner_account_id);
    assert_eq!(
        owner_account_id,
        serde_json::to_value(my_access_policy.into_account_id()).unwrap()
    );
    assert_eq!(my_balance, total_supply);
    assert_eq!(actual_total_supply, total_supply);
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_enclave_key_auto_notification() {
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
    let receipt = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithEnclaveKey",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();
    println!("deployed receipt: {:?}", receipt);

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
        .join_group(deployer_addr, gas, JOIN_GROUP_ENCLAVE_KEY_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();
    println!("init state receipt: {:?}", receipt);

    let req = json!({
        "access_policy": my_access_policy.clone(),
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    dispatcher.register_notification(encrypted_req).unwrap();

    // Get logs from contract and update state inside enclave.
    let updated_state = dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    let updated_state = dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_enclave_key_integration_eth_transfer() {
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
    let receipt = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithEnclaveKey",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();
    println!("deployed receipt: {:?}", receipt);

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
        .join_group(deployer_addr, gas, JOIN_GROUP_ENCLAVE_KEY_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();
    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
        .await
        .unwrap();

    // Get state from enclave
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
        .await
        .unwrap();

    // Check the updated states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_updated_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_updated_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let third_updated_state = dispatcher.get_state(encrypted_req).unwrap();

    assert_eq!(my_updated_state, 70);
    assert_eq!(other_updated_state, amount);
    assert_eq!(third_updated_state, 0);
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_enclave_key_integration_eth_approve() {
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
    let receipt = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithEnclaveKey",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();
    println!("deployed receipt: {:?}", receipt);

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
        .join_group(deployer_addr, gas, JOIN_GROUP_ENCLAVE_KEY_CMD)
        .await
        .unwrap();
    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_state = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_state = dispatcher.get_state(encrypted_req).unwrap();

    assert_eq!(my_state, amount);
    assert_eq!(other_state, 0);
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_enclave_key_integration_eth_transfer_from() {
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
    let receipt = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithEnclaveKey",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();
    println!("deployed receipt: {:?}", receipt);

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
        .join_group(deployer_addr, gas, JOIN_GROUP_ENCLAVE_KEY_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
        .await
        .unwrap();

    // Get initial state from enclave
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
        .await
        .unwrap();

    // Check the updated states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
        .await
        .unwrap();

    // Check the final states
    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_state_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let my_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": third_access_policy.clone(),
        "runtime_params": {
            "spender": spender
        },
        "state_name": "approved",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let third_state_approved = dispatcher.get_state(encrypted_req).unwrap();

    assert_eq!(my_state_approved, 10);
    assert_eq!(other_state_approved, 0);
    assert_eq!(third_state_approved, 0);
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_enclave_key_integration_eth_mint() {
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
    let receipt = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithEnclaveKey",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();
    println!("deployed receipt: {:?}", receipt);

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
        .join_group(deployer_addr, gas, JOIN_GROUP_ENCLAVE_KEY_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();

    println!("minted state receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
        .await
        .unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "total_supply",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    // Check the final states
    let actual_total_supply = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": my_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let owner_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy.clone(),
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_balance = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(actual_total_supply, 150);
    assert_eq!(owner_balance, 100);
    assert_eq!(other_balance, amount);
    assert!(!logs_contain("ERROR"));
}

#[actix_rt::test]
async fn test_enclave_key_integration_eth_burn() {
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
    let receipt = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithEnclaveKey",
            &*FACTORY_ABI_PATH,
            deployer_addr,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();
    println!("deployed receipt: {:?}", receipt);

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
        .join_group(deployer_addr, gas, JOIN_GROUP_ENCLAVE_KEY_CMD)
        .await
        .unwrap();

    // Get handshake from contract
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr.clone(),
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let receipt = dispatcher
        .send_command(
            encrypted_command,
            None,
            deployer_addr,
            gas,
            SEND_COMMAND_ENCLAVE_KEY_CMD,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher
        .fetch_events(FETCH_CIPHERTEXT_ENCLAVE_KEY_CMD, None)
        .await
        .unwrap();

    let req = json!({
        "access_policy": COMMON_ACCESS_POLICY.clone(),
        "runtime_params": {},
        "state_name": "total_supply",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    // Check the final states
    let actual_total_supply = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": my_access_policy,
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let owner_balance = dispatcher.get_state(encrypted_req).unwrap();

    let req = json!({
        "access_policy": other_access_policy,
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
    let other_balance = dispatcher.get_state(encrypted_req).unwrap();
    assert_eq!(actual_total_supply.as_u64().unwrap(), 80); // 100 - 20(burn)
    assert_eq!(owner_balance, 70); // 100 - 30(transfer)
    assert_eq!(other_balance, 10); // 30 - 20(burn)
    assert!(!logs_contain("ERROR"));
}
