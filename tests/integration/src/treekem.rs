#![cfg(test)]
use anonify_ecall_types::cmd::*;
use anonify_eth_driver::dispatcher::*;
use anonify_eth_driver::EventCache;
use eth_deployer::EthDeployer;
use frame_common::crypto::Ed25519ChallengeResponse;
use frame_config::ANONIFY_ABI_PATH;
use frame_config::{FACTORY_ABI_PATH, FACTORY_BIN_PATH};
use frame_host::EnclaveDir;
use frame_sodium::SodiumCiphertext;
use serde_json::json;

use crate::{
    get_enclave_encryption_key, set_env_vars, set_env_vars_for_treekem, ACCOUNT_INDEX,
    CONFIRMATIONS, ETH_URL, PASSWORD, CHAIN_ID, SIGNER_PRI_KEY,
};

#[actix_rt::test]
async fn test_treekem_key_rotation() {
    set_env_vars();
    set_env_vars_for_treekem();

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
    let signer = Signer::new(&SIGNER_PRI_KEY).unwrap();
    let factory_contract_addr = deployer
        .deploy(
            &*FACTORY_BIN_PATH,
            CONFIRMATIONS,
            gas,
            &*CHAIN_ID,
            signer,
        )
        .await
        .unwrap();
    let receipt = deployer
        .deploy_anonify_by_factory(
            "deployAnonifyWithTreeKem",
            &*FACTORY_ABI_PATH,
            signer,
            gas,
            factory_contract_addr,
            CONFIRMATIONS,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

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
        .fetch_events(
            FETCH_CIPHERTEXT_TREEKEM_CMD,
            Some(FETCH_HANDSHAKE_TREEKEM_CMD),
        )
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
        .fetch_events(
            FETCH_CIPHERTEXT_TREEKEM_CMD,
            Some(FETCH_HANDSHAKE_TREEKEM_CMD),
        )
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
        SodiumCiphertext::encrypt(&mut csprng, &pubkey, &serde_json::to_vec(&req).unwrap())
            .unwrap();
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
        .fetch_events(
            FETCH_CIPHERTEXT_TREEKEM_CMD,
            Some(FETCH_HANDSHAKE_TREEKEM_CMD),
        )
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
}
