use std::{
    sync::Arc,
};
use anonify_types::{RawPointer, ResultStatus};
use sgx_types::*;
use rand_core::RngCore;
use rand_os::OsRng;
use rand::Rng;
use ed25519_dalek::Keypair;
use anonify_common::{UserAddress, AccessRight, State};
use crate::auto_ffi::ecall_run_tests;
use crate::constants::*;
use crate::init_enclave::EnclaveDir;
use crate::ecalls::{init_state, get_state};
use crate::transaction::dispatcher::*;
use crate::mock::*;

const ETH_URL: &'static str = "http://172.18.0.2:8545";
const ANONYMOUS_ASSET_ABI_PATH: &str = "../../build/AnonymousAsset.abi";

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
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let mut csprng: OsRng = OsRng::new().unwrap();
    let my_access_right = AccessRight::new_from_rng(&mut csprng);
    let other_access_right = AccessRight::new_from_rng(&mut csprng);
    let third_access_right = AccessRight::new_from_rng(&mut csprng);

    let total_supply = 100;
    let event_db = Arc::new(EventDB::new());
    let event = EthEvent::build_event();

    // 1. Deploy
    let mut deployer = EthDeployer::new(eid, ETH_URL).unwrap();
    let deployer_addr = deployer.get_account(0).unwrap();
    let contract_addr = deployer.deploy(&deployer_addr, &my_access_right, MockState::new(total_supply)).unwrap();

    println!("Deployer address: {}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);

    let contract = deployer.get_contract(ANONYMOUS_ASSET_ABI_PATH).unwrap();


    // 2. Get logs from contract and update state inside enclave.
    let contract_addr = hex::encode(contract_addr.as_bytes());
    println!("{:?}", contract_addr);
    let ev_watcher = EventWatcher::new(
        &ETH_URL,
        ANONYMOUS_ASSET_ABI_PATH,
        &contract_addr,
        event_db.clone(),
    ).unwrap();
    ev_watcher.block_on_event(eid).unwrap();


    // 3. Get state from enclave
    let my_state = get_state_by_access_right::<MockState>(&my_access_right, eid).unwrap();
    let other_state = get_state_by_access_right::<MockState>(&other_access_right, eid).unwrap();
    let third_state = get_state_by_access_right::<MockState>(&third_access_right, eid).unwrap();
    assert_eq!(my_state.into_raw(), total_supply);
    assert_eq!(other_state.into_raw(), 0);
    assert_eq!(third_state.into_raw(), 0);


    // 4. Send a transaction to contract
    let amount = 30;
    let gas = 3_000_000;
    let other_user_address = other_access_right.user_address();

    let eth_sender = EthSender::from_contract(eid, contract);
    let receipt = eth_sender.send_tx(
            &my_access_right,
            &other_user_address,
            MockState::new(amount),
            deployer_addr,
            gas
        );

    println!("receipt: {:?}", receipt);


    // 5. Update state inside enclave
    let ev_watcher = EventWatcher::new(
        &ETH_URL,
        ANONYMOUS_ASSET_ABI_PATH,
        &contract_addr,
        event_db.clone(),
    ).unwrap();
    ev_watcher.block_on_event(eid).unwrap();


    // 6. Check the updated states
    let my_updated_state = get_state_by_access_right::<MockState>(&my_access_right, eid).unwrap();
    let other_updated_state = get_state_by_access_right::<MockState>(&other_access_right, eid).unwrap();
    let third_updated_state = get_state_by_access_right::<MockState>(&third_access_right, eid).unwrap();

    assert_eq!(my_updated_state.into_raw(), total_supply - amount);
    assert_eq!(other_updated_state.into_raw(), amount);
    assert_eq!(third_updated_state.into_raw(), 0);
}
