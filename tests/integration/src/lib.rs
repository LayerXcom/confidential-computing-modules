use std::{
    sync::Arc,
    env,
    collections::BTreeMap,
};
use sgx_types::*;
use anonify_common::{AccessRight, UserAddress, COMMON_ACCESS_RIGHT};
use anonify_runtime::{State, U64, Approved};
use erc20_state_transition::{transfer, construct, approve, transfer_from, mint, burn};
use anonify_bc_connector::{
    eventdb::{EventDB, BlockNumDB},
    eth::*,
};
use anonify_host::{
    init_enclave::EnclaveDir,
    dispatcher::*,
};

const ETH_URL: &'static str = "http://172.18.0.2:8545";
const ANONYMOUS_ASSET_ABI_PATH: &str = "../../build/Anonify.abi";

#[test]
fn test_integration_eth_construct() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_right = AccessRight::new_from_rng().unwrap();

    let state_id = 0;
    let gas = 3_000_000;
    let event_db = Arc::new(EventDB::new());
    let dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
    dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct{ total_supply };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        init_state,
        state_id,
        "construct",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();

    println!("init state receipt: {}", receipt);


    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // Get state from enclave
    let owner_address = get_state::<UserAddress>(&*COMMON_ACCESS_RIGHT, eid, "Owner").unwrap();
    let my_balance = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let actual_total_supply = get_state::<U64>(&*COMMON_ACCESS_RIGHT, eid, "TotalSupply").unwrap();
    assert_eq!(owner_address, my_access_right.user_address());
    assert_eq!(my_balance, total_supply);
    assert_eq!(actual_total_supply, total_supply);
}

#[test]
fn test_auto_notification() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_right = AccessRight::new_from_rng().unwrap();
    let other_access_right = AccessRight::new_from_rng().unwrap();
    let third_access_right = AccessRight::new_from_rng().unwrap();

    let state_id = 0;
    let gas = 3_000_000;
    let event_db = Arc::new(EventDB::new());
    let dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
    dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct{ total_supply };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        init_state,
        state_id,
        "construct",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();

    println!("init state receipt: {}", receipt);

    // Get logs from contract and update state inside enclave.
    let updated_state = dispatcher
        .block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap().unwrap();

    assert_eq!(updated_state.len(), 1);
    assert_eq!(updated_state[0].address, my_access_right.user_address());
    assert_eq!(updated_state[0].mem_id.as_raw(), 0);
    assert_eq!(updated_state[0].state, total_supply);

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let recipient = other_access_right.user_address();
    let transfer_state = transfer{ amount, recipient };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        transfer_state,
        state_id,
        "transfer",
        deployer_addr,
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();
    println!("receipt: {}", receipt);

    // Update state inside enclave
    let updated_state = dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap().unwrap();

    assert_eq!(updated_state.len(), 1);
    assert_eq!(updated_state[0].address, my_access_right.user_address());
    assert_eq!(updated_state[0].mem_id.as_raw(), 0);
    assert_eq!(updated_state[0].state, U64::from_raw(70));
}

#[test]
fn test_integration_eth_transfer() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_right = AccessRight::new_from_rng().unwrap();
    let other_access_right = AccessRight::new_from_rng().unwrap();
    let third_access_right = AccessRight::new_from_rng().unwrap();

    let state_id = 0;
    let gas = 3_000_000;
    let event_db = Arc::new(EventDB::new());
    let dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
    dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct{ total_supply };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        init_state,
        state_id,
        "construct",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();

    println!("init state receipt: {}", receipt);


    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // Get state from enclave
    let my_state = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_state = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    let third_state = get_state::<U64>(&third_access_right, eid, "Balance").unwrap();
    assert_eq!(my_state, total_supply);
    assert_eq!(other_state, U64::zero());
    assert_eq!(third_state, U64::zero());


    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let recipient = other_access_right.user_address();
    let transfer_state = transfer{ amount, recipient };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        transfer_state,
        state_id,
        "transfer",
        deployer_addr,
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();
    println!("receipt: {}", receipt);

    // Update state inside enclave
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // Check the updated states
    let my_updated_state = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_updated_state = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    let third_updated_state = get_state::<U64>(&third_access_right, eid, "Balance").unwrap();

    assert_eq!(my_updated_state, U64::from_raw(70));
    assert_eq!(other_updated_state, amount);
    assert_eq!(third_updated_state, U64::zero());
}

#[test]
fn test_key_rotation() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_right = AccessRight::new_from_rng().unwrap();
    let other_access_right = AccessRight::new_from_rng().unwrap();
    let third_access_right = AccessRight::new_from_rng().unwrap();

    let state_id = 0;
    let gas = 3_000_000;
    let event_db = Arc::new(EventDB::new());
    let dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
    dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Send handshake
    let receipt = dispatcher.handshake(deployer_addr.clone(), gas, &contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("handshake receipt: {}", receipt);

    // Get handshake from contract
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // init state
    let total_supply = U64::from_raw(100);
    let init_state = construct{ total_supply };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        init_state,
        state_id,
        "construct",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();
    println!("init state receipt: {}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Get state from enclave
    let my_state = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_state = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    let third_state = get_state::<U64>(&third_access_right, eid, "Balance").unwrap();
    assert_eq!(my_state, total_supply);
    assert_eq!(other_state, U64::zero());
    assert_eq!(third_state, U64::zero());
}

#[test]
fn test_integration_eth_approve() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_right = AccessRight::new_from_rng().unwrap();
    let other_access_right = AccessRight::new_from_rng().unwrap();

    let state_id = 0;
    let gas = 3_000_000;
    let event_db = Arc::new(EventDB::new());
    let dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
    dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        init_state,
        state_id,
        "construct",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();

    println!("init state receipt: {}", receipt);


    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Get state from enclave
    let my_state = get_state::<Approved>(&my_access_right, eid, "Approved").unwrap();
    let other_state = get_state::<Approved>(&other_access_right, eid, "Approved").unwrap();
    assert_eq!(my_state, Approved::default());
    assert_eq!(other_state, Approved::default());

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let spender = other_access_right.user_address();
    let approve_state = approve { amount, spender };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        approve_state,
        state_id,
        "approve",
        deployer_addr,
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();
    println!("receipt: {}", receipt);


    // Update state inside enclave
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // Check the updated states
    let my_state = get_state::<Approved>(&my_access_right, eid, "Approved").unwrap();
    let other_state = get_state::<Approved>(&other_access_right, eid, "Approved").unwrap();
    let want_my_state = Approved::new({
        let mut bt = BTreeMap::new();
        bt.insert(spender, amount);
        bt
    });
    assert_eq!(my_state, want_my_state);
    assert_eq!(other_state, Approved::default());
}

#[test]
fn test_integration_eth_transfer_from() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_right = AccessRight::new_from_rng().unwrap();
    let other_access_right = AccessRight::new_from_rng().unwrap();
    let third_access_right = AccessRight::new_from_rng().unwrap();

    let state_id = 0;
    let gas = 3_000_000;
    let event_db = Arc::new(EventDB::new());
    let dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
    dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct { total_supply };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        init_state,
        state_id,
        "construct",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();

    println!("init state receipt: {}", receipt);


    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Get initial state from enclave
    let my_state_balance = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_state_balance = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    let third_state_balance = get_state::<U64>(&third_access_right, eid, "Balance").unwrap();
    assert_eq!(my_state_balance, U64::from_raw(100));
    assert_eq!(other_state_balance, U64::zero());
    assert_eq!(third_state_balance, U64::zero());

    let my_state_approved = get_state::<Approved>(&my_access_right, eid, "Approved").unwrap();
    let other_state_approved = get_state::<Approved>(&other_access_right, eid, "Approved").unwrap();
    let third_state_approved = get_state::<Approved>(&third_access_right, eid, "Approved").unwrap();
    assert_eq!(my_state_approved, Approved::default());
    assert_eq!(other_state_approved, Approved::default());
    assert_eq!(third_state_approved, Approved::default());

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let spender = other_access_right.user_address();
    let approve_state = approve { amount, spender };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        approve_state,
        state_id,
        "approve",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();
    println!("receipt: {}", receipt);


    // Update state inside enclave
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Check the updated states
    let my_state_balance = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_state_balance = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    let third_state_balance = get_state::<U64>(&third_access_right, eid, "Balance").unwrap();
    assert_eq!(my_state_balance, U64::from_raw(100));
    assert_eq!(other_state_balance, U64::zero());
    assert_eq!(third_state_balance, U64::zero());

    let my_state_approved = get_state::<Approved>(&my_access_right, eid, "Approved").unwrap();
    let other_state_approved = get_state::<Approved>(&other_access_right, eid, "Approved").unwrap();
    let third_state_approved = get_state::<Approved>(&third_access_right, eid, "Approved").unwrap();
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
    let owner = my_access_right.user_address();
    let recipient = third_access_right.user_address();
    let transferred_from_state = transfer_from { owner, recipient, amount };
    let receipt = dispatcher.send_instruction(
        other_access_right.clone(),
        transferred_from_state,
        state_id,
        "transfer_from",
        deployer_addr,
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();
    println!("receipt: {}", receipt);


    // Update state inside enclave
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Check the final states
    let my_state_balance = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_state_balance = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    let third_state_balance = get_state::<U64>(&third_access_right, eid, "Balance").unwrap();
    assert_eq!(my_state_balance, U64::from_raw(80));
    assert_eq!(other_state_balance, U64::zero());
    assert_eq!(third_state_balance, U64::from_raw(20));

    let my_state_approved = get_state::<Approved>(&my_access_right, eid, "Approved").unwrap();
    let other_state_approved = get_state::<Approved>(&other_access_right, eid, "Approved").unwrap();
    let third_state_approved = get_state::<Approved>(&third_access_right, eid, "Approved").unwrap();
    let want_my_state = Approved::new({
        let mut bt = BTreeMap::new();
        bt.insert(spender, U64::from_raw(10));
        bt
    });
    assert_eq!(my_state_approved, want_my_state);
    assert_eq!(other_state_approved, Approved::default());
    assert_eq!(third_state_approved, Approved::default());
}

#[test]
fn test_integration_eth_mint() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_right = AccessRight::new_from_rng().unwrap();
    let other_access_right = AccessRight::new_from_rng().unwrap();

    let state_id = 0;
    let gas = 3_000_000;
    let event_db = Arc::new(EventDB::new());
    let dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
    dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct{ total_supply };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        init_state,
        state_id,
        "construct",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();

    println!("init state receipt: {}", receipt);


    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // transit state
    let amount = U64::from_raw(50);
    let recipient = other_access_right.user_address();
    let minting_state = mint{ amount, recipient };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        minting_state,
        state_id,
        "mint",
        deployer_addr,
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();

    println!("minted state receipt: {}", receipt);


    // Update state inside enclave
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // Check the final states
    let actual_total_supply = get_state::<U64>(&*COMMON_ACCESS_RIGHT, eid, "TotalSupply").unwrap();
    let owner_balance = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_balance = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    assert_eq!(actual_total_supply, U64::from_raw(150));
    assert_eq!(owner_balance, U64::from_raw(100));
    assert_eq!(other_balance, amount);
}

#[test]
fn test_integration_eth_burn() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_right = AccessRight::new_from_rng().unwrap();
    let other_access_right = AccessRight::new_from_rng().unwrap();

    let state_id = 0;
    let gas = 3_000_000;
    let event_db = Arc::new(EventDB::new());
    let dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

    // Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
    dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    // Get handshake from contract
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let init_state = construct{ total_supply };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        init_state,
        state_id,
        "construct",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();

    println!("init state receipt: {}", receipt);


    // Get logs from contract and update state inside enclave.
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let recipient = other_access_right.user_address();
    let transfer_state = transfer{ amount, recipient };
    let receipt = dispatcher.send_instruction(
        my_access_right.clone(),
        transfer_state,
        state_id,
        "transfer",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();
    println!("receipt: {}", receipt);


    // Update state inside enclave
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // Send a transaction to contract
    let amount = U64::from_raw(20);
    let burn_state = burn{ amount };
    let receipt = dispatcher.send_instruction(
        other_access_right.clone(),
        burn_state,
        state_id,
        "burn",
        deployer_addr,
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();
    println!("receipt: {}", receipt);


    // Update state inside enclave
    dispatcher.block_on_event::<_, U64>(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // Check the final states
    let actual_total_supply = get_state::<U64>(&*COMMON_ACCESS_RIGHT, eid, "TotalSupply").unwrap();
    let owner_balance = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_balance = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    assert_eq!(actual_total_supply, U64::from_raw(80)); // 100 - 20(burn)
    assert_eq!(owner_balance, U64::from_raw(70)); // 100 - 30(transfer)
    assert_eq!(other_balance, U64::from_raw(10)); // 30 - 20(burn)
}
