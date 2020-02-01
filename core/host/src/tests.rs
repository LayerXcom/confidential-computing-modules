use std::{
    sync::Arc,
};
use anonify_types::{RawPointer, ResultStatus};
use sgx_types::*;
use rand_os::OsRng;
use anonify_common::{AccessRight, State};
use crate::auto_ffi::ecall_run_tests;
use crate::init_enclave::EnclaveDir;
use crate::transaction::{
    dispatcher::*,
    eventdb::EventDB,
    eth::client::*,
    utils::get_state_by_access_right,
};
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
    let mut dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new_with_deployer(eid, ETH_URL, event_db).unwrap();

    // 1. Deploy
    let deployer_addr = dispatcher.get_account(0).unwrap();
    let contract_addr = dispatcher.deploy(&deployer_addr, &my_access_right, MockState::new(total_supply)).unwrap();
    dispatcher.set_contract_addr(&contract_addr).unwrap();
    println!("Deployer address: {:?}", deployer_addr);
    println!("deployed contract address: {}", contract_addr);


    // 2. Get logs from contract and update state inside enclave.
    dispatcher.block_on_event().unwrap();


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
    let receipt = dispatcher.send_tx(
            &my_access_right,
            &other_user_address,
            MockState::new(amount),
            deployer_addr,
            gas
        );
    println!("receipt: {:?}", receipt);


    // 5. Update state inside enclave
    dispatcher.block_on_event().unwrap();


    // 6. Check the updated states
    let my_updated_state = get_state_by_access_right::<MockState>(&my_access_right, eid).unwrap();
    let other_updated_state = get_state_by_access_right::<MockState>(&other_access_right, eid).unwrap();
    let third_updated_state = get_state_by_access_right::<MockState>(&third_access_right, eid).unwrap();

    assert_eq!(my_updated_state.into_raw(), total_supply - amount);
    assert_eq!(other_updated_state.into_raw(), amount);
    assert_eq!(third_updated_state.into_raw(), 0);
}
