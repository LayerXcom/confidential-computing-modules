use anonify_eth_driver::{dispatcher::*, eth::*, EventCache};
use erc20_state_transition::{
    approve, burn, construct, mint, transfer, transfer_from, CallName, MemName, CIPHERTEXT_SIZE,
};
use frame_common::{
    crypto::{AccountId, Ed25519ChallengeResponse, COMMON_ACCESS_POLICY},
    traits::*,
};
use frame_host::EnclaveDir;
use frame_runtime::primitives::{Approved, U64};
use parking_lot::RwLock;
use sgx_types::*;
use std::{collections::BTreeMap, env, sync::Arc};

const ETH_URL: &'static str = "http://172.28.0.2:8545";
const ABI_PATH: &str = "../../contract-build/Anonify.abi";
const BIN_PATH: &str = "../../contract-build/Anonify.bin";
const CONFIRMATIONS: usize = 0;
const ACCOUNT_INDEX: usize = 0;
const PASSWORD: &str = "anonify0101";

#[actix_rt::test]
async fn test_integration_eth_construct() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = Arc::new(RwLock::new(EventCache::default()));
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(ACCOUNT_INDEX, PASSWORD).await.unwrap();
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
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            init_state,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Get state from enclave
    let owner_account_id =
        get_state::<AccountId, MemName, _>(COMMON_ACCESS_POLICY.clone(), eid, "Owner").unwrap();
    let my_balance =
        get_state::<U64, MemName, _>(my_access_policy.clone(), eid, "Balance").unwrap();
    let actual_total_supply =
        get_state::<U64, MemName, _>(COMMON_ACCESS_POLICY.clone(), eid, "TotalSupply").unwrap();
    assert_eq!(owner_account_id, my_access_policy.into_account_id());
    assert_eq!(my_balance, total_supply);
    assert_eq!(actual_total_supply, total_supply);
}

#[actix_rt::test]
async fn test_auto_notification() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let third_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = Arc::new(RwLock::new(EventCache::default()));
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(ACCOUNT_INDEX, PASSWORD).await.unwrap();
    let (contract_addr, _) = dispatcher
        .deploy(
            deployer_addr.clone(),
            gas,
            ABI_PATH,
            BIN_PATH,
            CONFIRMATIONS,
        ).await
        .unwrap();
    dispatcher
        .set_contract_addr(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            init_state,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    let updated_state = dispatcher.block_on_event::<U64>().await.unwrap().unwrap();

    assert_eq!(updated_state.len(), 1);
    assert_eq!(
        updated_state[0].account_id,
        my_access_policy.into_account_id()
    );
    assert_eq!(updated_state[0].mem_id.as_raw(), 0);
    assert_eq!(updated_state[0].state, total_supply);

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let recipient = other_access_policy.into_account_id();
    let transfer_state = transfer { amount, recipient };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            transfer_state,
            "transfer",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    let updated_state = dispatcher.block_on_event::<U64>().await.unwrap().unwrap();

    assert_eq!(updated_state.len(), 1);
    assert_eq!(
        updated_state[0].account_id,
        my_access_policy.into_account_id()
    );
    assert_eq!(updated_state[0].mem_id.as_raw(), 0);
    assert_eq!(updated_state[0].state, U64::from_raw(70));
}

#[actix_rt::test]
async fn test_integration_eth_transfer() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let third_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = Arc::new(RwLock::new(EventCache::default()));
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(ACCOUNT_INDEX, PASSWORD).await.unwrap();
    let (contract_addr, _) = dispatcher
        .deploy(
            deployer_addr.clone(),
            gas,
            ABI_PATH,
            BIN_PATH,
            CONFIRMATIONS,
        ).await
        .unwrap();
    dispatcher
        .set_contract_addr(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            init_state,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Get state from enclave
    let my_state = get_state::<U64, MemName, _>(my_access_policy.clone(), eid, "Balance").unwrap();
    let other_state =
        get_state::<U64, MemName, _>(other_access_policy.clone(), eid, "Balance").unwrap();
    let third_state =
        get_state::<U64, MemName, _>(third_access_policy.clone(), eid, "Balance").unwrap();
    assert_eq!(my_state, total_supply);
    assert_eq!(other_state, U64::zero());
    assert_eq!(third_state, U64::zero());

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let recipient = other_access_policy.into_account_id();
    let transfer_state = transfer { amount, recipient };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            transfer_state,
            "transfer",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Check the updated states
    let my_updated_state = get_state::<U64, MemName, _>(my_access_policy, eid, "Balance").unwrap();
    let other_updated_state =
        get_state::<U64, MemName, _>(other_access_policy, eid, "Balance").unwrap();
    let third_updated_state =
        get_state::<U64, MemName, _>(third_access_policy, eid, "Balance").unwrap();

    assert_eq!(my_updated_state, U64::from_raw(70));
    assert_eq!(other_updated_state, amount);
    assert_eq!(third_updated_state, U64::zero());
}

#[actix_rt::test]
async fn test_key_rotation() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let third_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = Arc::new(RwLock::new(EventCache::default()));
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(ACCOUNT_INDEX, PASSWORD).await.unwrap();
    let (contract_addr, _) = dispatcher
        .deploy(
            deployer_addr.clone(),
            gas,
            ABI_PATH,
            BIN_PATH,
            CONFIRMATIONS,
        ).await
        .unwrap();
    dispatcher
        .set_contract_addr(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Send handshake
    let (receipt, _) = dispatcher
        .handshake(deployer_addr.clone(), gas)
        .await
        .unwrap();
    println!("handshake receipt: {:?}", receipt);

    // Get handshake from contract
    dispatcher.block_on_event::<U64>().await.unwrap();

    // init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            init_state,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();
    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Get state from enclave
    let my_state = get_state::<U64, MemName, _>(my_access_policy, eid, "Balance").unwrap();
    let other_state = get_state::<U64, MemName, _>(other_access_policy, eid, "Balance").unwrap();
    let third_state = get_state::<U64, MemName, _>(third_access_policy, eid, "Balance").unwrap();
    assert_eq!(my_state, total_supply);
    assert_eq!(other_state, U64::zero());
    assert_eq!(third_state, U64::zero());
}

#[actix_rt::test]
async fn test_integration_eth_approve() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = Arc::new(RwLock::new(EventCache::default()));
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(ACCOUNT_INDEX, PASSWORD).await.unwrap();
    let (contract_addr, _) = dispatcher
        .deploy(
            deployer_addr.clone(),
            gas,
            ABI_PATH,
            BIN_PATH,
            CONFIRMATIONS,
        ).await
        .unwrap();
    dispatcher
        .set_contract_addr(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            init_state,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Get state from enclave
    let my_state =
        get_state::<Approved, MemName, _>(my_access_policy.clone(), eid, "Approved").unwrap();
    let other_state =
        get_state::<Approved, MemName, _>(other_access_policy.clone(), eid, "Approved").unwrap();
    assert_eq!(my_state, Approved::default());
    assert_eq!(other_state, Approved::default());

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let spender = other_access_policy.into_account_id();
    let approve_state = approve { amount, spender };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            approve_state,
            "approve",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Check the updated states
    let my_state = get_state::<Approved, MemName, _>(my_access_policy, eid, "Approved").unwrap();
    let other_state =
        get_state::<Approved, MemName, _>(other_access_policy, eid, "Approved").unwrap();
    let want_my_state = Approved::new({
        let mut bt = BTreeMap::new();
        bt.insert(spender, amount);
        bt
    });
    assert_eq!(my_state, want_my_state);
    assert_eq!(other_state, Approved::default());
}

#[actix_rt::test]
async fn test_integration_eth_transfer_from() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let third_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = Arc::new(RwLock::new(EventCache::default()));
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(ACCOUNT_INDEX, PASSWORD).await.unwrap();
    let (contract_addr, _) = dispatcher
        .deploy(
            deployer_addr.clone(),
            gas,
            ABI_PATH,
            BIN_PATH,
            CONFIRMATIONS,
        ).await
        .unwrap();
    dispatcher
        .set_contract_addr(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            init_state,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Get initial state from enclave
    let my_state_balance =
        get_state::<U64, MemName, _>(my_access_policy.clone(), eid, "Balance").unwrap();
    let other_state_balance =
        get_state::<U64, MemName, _>(other_access_policy.clone(), eid, "Balance").unwrap();
    let third_state_balance =
        get_state::<U64, MemName, _>(third_access_policy.clone(), eid, "Balance").unwrap();
    assert_eq!(my_state_balance, U64::from_raw(100));
    assert_eq!(other_state_balance, U64::zero());
    assert_eq!(third_state_balance, U64::zero());

    let my_state_approved =
        get_state::<Approved, MemName, _>(my_access_policy.clone(), eid, "Approved").unwrap();
    let other_state_approved =
        get_state::<Approved, MemName, _>(other_access_policy.clone(), eid, "Approved").unwrap();
    let third_state_approved =
        get_state::<Approved, MemName, _>(third_access_policy.clone(), eid, "Approved").unwrap();
    assert_eq!(my_state_approved, Approved::default());
    assert_eq!(other_state_approved, Approved::default());
    assert_eq!(third_state_approved, Approved::default());

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let spender = other_access_policy.into_account_id();
    let approve_state = approve { amount, spender };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            approve_state,
            "approve",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Check the updated states
    let my_state_balance =
        get_state::<U64, MemName, _>(my_access_policy.clone(), eid, "Balance").unwrap();
    let other_state_balance =
        get_state::<U64, MemName, _>(other_access_policy.clone(), eid, "Balance").unwrap();
    let third_state_balance =
        get_state::<U64, MemName, _>(third_access_policy.clone(), eid, "Balance").unwrap();
    assert_eq!(my_state_balance, U64::from_raw(100));
    assert_eq!(other_state_balance, U64::zero());
    assert_eq!(third_state_balance, U64::zero());

    let my_state_approved =
        get_state::<Approved, MemName, _>(my_access_policy.clone(), eid, "Approved").unwrap();
    let other_state_approved =
        get_state::<Approved, MemName, _>(other_access_policy.clone(), eid, "Approved").unwrap();
    let third_state_approved =
        get_state::<Approved, MemName, _>(third_access_policy.clone(), eid, "Approved").unwrap();
    let want_my_state = Approved::new({
        let mut bt = BTreeMap::new();
        bt.insert(spender, amount);
        bt
    });
    assert_eq!(my_state_approved, want_my_state);
    assert_eq!(other_state_approved, Approved::default());
    assert_eq!(third_state_approved, Approved::default());

    // Send a transaction to contract
    let amount = U64::from_raw(20);
    let owner = my_access_policy.into_account_id();
    let recipient = third_access_policy.into_account_id();
    let transferred_from_state = transfer_from {
        owner,
        recipient,
        amount,
    };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            other_access_policy.clone(),
            transferred_from_state,
            "transfer_from",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Check the final states
    let my_state_balance =
        get_state::<U64, MemName, _>(my_access_policy.clone(), eid, "Balance").unwrap();
    let other_state_balance =
        get_state::<U64, MemName, _>(other_access_policy.clone(), eid, "Balance").unwrap();
    let third_state_balance =
        get_state::<U64, MemName, _>(third_access_policy.clone(), eid, "Balance").unwrap();
    assert_eq!(my_state_balance, U64::from_raw(80));
    assert_eq!(other_state_balance, U64::zero());
    assert_eq!(third_state_balance, U64::from_raw(20));

    let my_state_approved =
        get_state::<Approved, MemName, _>(my_access_policy, eid, "Approved").unwrap();
    let other_state_approved =
        get_state::<Approved, MemName, _>(other_access_policy, eid, "Approved").unwrap();
    let third_state_approved =
        get_state::<Approved, MemName, _>(third_access_policy, eid, "Approved").unwrap();
    let want_my_state = Approved::new({
        let mut bt = BTreeMap::new();
        bt.insert(spender, U64::from_raw(10));
        bt
    });
    assert_eq!(my_state_approved, want_my_state);
    assert_eq!(other_state_approved, Approved::default());
    assert_eq!(third_state_approved, Approved::default());
}

#[actix_rt::test]
async fn test_integration_eth_mint() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = Arc::new(RwLock::new(EventCache::default()));
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(ACCOUNT_INDEX, PASSWORD).await.unwrap();
    let (contract_addr, _) = dispatcher
        .deploy(
            deployer_addr.clone(),
            gas,
            ABI_PATH,
            BIN_PATH,
            CONFIRMATIONS,
        ).await
        .unwrap();
    dispatcher
        .set_contract_addr(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            init_state,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<U64>().await.unwrap();

    // transit state
    let amount = U64::from_raw(50);
    let recipient = other_access_policy.into_account_id();
    let minting_state = mint { amount, recipient };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            minting_state,
            "mint",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();

    println!("minted state receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Check the final states
    let actual_total_supply =
        get_state::<U64, MemName, _>(COMMON_ACCESS_POLICY.clone(), eid, "TotalSupply").unwrap();
    let owner_balance = get_state::<U64, MemName, _>(my_access_policy, eid, "Balance").unwrap();
    let other_balance = get_state::<U64, MemName, _>(other_access_policy, eid, "Balance").unwrap();
    assert_eq!(actual_total_supply, U64::from_raw(150));
    assert_eq!(owner_balance, U64::from_raw(100));
    assert_eq!(other_balance, amount);
}

#[actix_rt::test]
async fn test_integration_eth_burn() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();
    let other_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = Arc::new(RwLock::new(EventCache::default()));
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(ACCOUNT_INDEX, PASSWORD).await.unwrap();
    let (contract_addr, _) = dispatcher
        .deploy(
            deployer_addr.clone(),
            gas,
            ABI_PATH,
            BIN_PATH,
            CONFIRMATIONS,
        ).await
        .unwrap();
    dispatcher
        .set_contract_addr(&contract_addr, ABI_PATH)
        .unwrap();
    println!("Deployer account_id: {:?}", deployer_addr);
    println!("deployed contract account_id: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            init_state,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let recipient = other_access_policy.into_account_id();
    let transfer_state = transfer { amount, recipient };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            my_access_policy.clone(),
            transfer_state,
            "transfer",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Send a transaction to contract
    let amount = U64::from_raw(20);
    let burn_state = burn { amount };
    let receipt = dispatcher
        .send_instruction::<_, CallName, _>(
            other_access_policy.clone(),
            burn_state,
            "burn",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.block_on_event::<U64>().await.unwrap();

    // Check the final states
    let actual_total_supply =
        get_state::<U64, MemName, _>(COMMON_ACCESS_POLICY.clone(), eid, "TotalSupply").unwrap();
    let owner_balance = get_state::<U64, MemName, _>(my_access_policy, eid, "Balance").unwrap();
    let other_balance = get_state::<U64, MemName, _>(other_access_policy, eid, "Balance").unwrap();
    assert_eq!(actual_total_supply, U64::from_raw(80)); // 100 - 20(burn)
    assert_eq!(owner_balance, U64::from_raw(70)); // 100 - 30(transfer)
    assert_eq!(other_balance, U64::from_raw(10)); // 30 - 20(burn)
}

pub fn set_env_vars() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    env::set_var("SPID", "2C149BFC94A61D306A96211AED155BE9");
    env::set_var(
        "IAS_URL",
        "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report",
    );
    env::set_var("SUB_KEY", "77e2533de0624df28dc3be3a5b9e50d9");
    env::set_var("AUDITOR_ENDPOINT", "test");
}
