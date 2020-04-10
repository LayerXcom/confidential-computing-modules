use std::{sync::Arc, env};
use anonify_types::{RawPointer, ResultStatus};
use sgx_types::*;
use rand_os::OsRng;
use anonify_common::AccessRight;
use anonify_runtime::{State, U64};
use anonify_app_preluder::{transfer, constructor};
use anonify_event_watcher::{
    eventdb::{EventDB, BlockNumDB},
    eth::*,
};
use crate::auto_ffi::ecall_run_tests;
use crate::init_enclave::EnclaveDir;
use crate::dispatcher::*;

const ETH_URL: &'static str = "http://172.18.0.2:8545";
const ANONYMOUS_ASSET_ABI_PATH: &str = "../../build/Anonify.abi";

#[test]
fn test_in_enclave() {
    let mut tmp = 3;
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let ptr = unsafe { RawPointer::new_mut(&mut tmp) };
    let mut res = ResultStatus::Ok;
    let ret = unsafe { ecall_run_tests(
        enclave.geteid(),
        &ptr as *const RawPointer,
        &mut res,
    ) };

    assert_eq!(ret, sgx_status_t::SGX_SUCCESS);
    assert_eq!(res, ResultStatus::Ok);
}

#[test]
fn test_integration_eth_transfer() {
    env::set_var("MY_ROSTER_IDX", "0");
    env::set_var("MAX_ROSTER_IDX", "2");
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let mut csprng: OsRng = OsRng::new().unwrap();
    let my_access_right = AccessRight::new_from_rng(&mut csprng);
    let other_access_right = AccessRight::new_from_rng(&mut csprng);
    let third_access_right = AccessRight::new_from_rng(&mut csprng);

    let state_id = 0;
    let gas = 3_000_000;
    let event_db = Arc::new(EventDB::new());
    let mut dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

    // 1. Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
    dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    // 1.5. Get handshake from contract
    dispatcher.block_on_event(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

    // 2. init state
    let total_supply = U64::from_raw(100);
    let init_state = constructor{ total_supply };
    let receipt = dispatcher.state_transition(
        my_access_right.clone(),
        init_state,
        state_id,
        "constructor",
        deployer_addr.clone(),
        gas,
        &contract_addr,
        ANONYMOUS_ASSET_ABI_PATH,
    ).unwrap();

    println!("init state receipt: {}", receipt);


    // 3. Get logs from contract and update state inside enclave.
    dispatcher.block_on_event(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // 4. Get state from enclave
    let my_state = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_state = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    let third_state = get_state::<U64>(&third_access_right, eid, "Balance").unwrap();
    assert_eq!(my_state, total_supply);
    assert_eq!(other_state, U64::zero());
    assert_eq!(third_state, U64::zero());


    // 5. Send a transaction to contract
    let amount = U64::from_raw(30);
    let recipient = other_access_right.user_address();
    let transfer_state = transfer{ amount, recipient };
    let receipt = dispatcher.state_transition(
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


    // 6. Update state inside enclave
    dispatcher.block_on_event(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // 7. Check the updated states
    let my_updated_state = get_state::<U64>(&my_access_right, eid, "Balance").unwrap();
    let other_updated_state = get_state::<U64>(&other_access_right, eid, "Balance").unwrap();
    let third_updated_state = get_state::<U64>(&third_access_right, eid, "Balance").unwrap();

    assert_eq!(my_updated_state, U64::from_raw(70));
    assert_eq!(other_updated_state, amount);
    assert_eq!(third_updated_state, U64::zero());
}
