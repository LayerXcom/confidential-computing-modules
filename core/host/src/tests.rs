use std::{
    sync::Arc,
    io::{self, Read, Write},
    ops::{Add, Sub},
};
use anonify_types::{RawPointer, ResultStatus};
use byteorder::{ByteOrder, LittleEndian};
use sgx_types::*;
use rand_core::RngCore;
use rand_os::OsRng;
use rand::Rng;
use ed25519_dalek::Keypair;
use anonify_common::{UserAddress, AccessRight, State};
use serde::{Serialize, Deserialize};
use crate::auto_ffi::ecall_run_tests;
use crate::constants::*;
use crate::init_enclave::EnclaveDir;
use crate::ecalls::{init_state, get_state};
use crate::prelude::*;
use crate::web3::*;

const ETH_URL: &'static str = "http://172.18.0.2:8545";
const ANONYMOUS_ASSET_ABI_PATH: &str = "../../build/AnonymousAsset.abi";

const MOCK_STATE_LENGTH: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
// #[serde(crate = "crate::serde")]
pub struct MockState(u64);

impl State for MockState {
    fn new(init: u64) -> Self {
        MockState(init)
    }

    fn as_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(MOCK_STATE_LENGTH);
        self.write_le(&mut buf)?;
        Ok(buf)
    }

    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let mut buf = bytes;
        Self::read_le(&mut buf)
    }

    fn write_le<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut buf = [0u8; MOCK_STATE_LENGTH];
        LittleEndian::write_u64(&mut buf, self.0);
        writer.write_all(&buf)?;

        Ok(())
    }

    fn read_le<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; MOCK_STATE_LENGTH];
        reader.read_exact(&mut buf)?;
        let res = LittleEndian::read_u64(&buf);

        Ok(MockState(res))
    }
}

impl Add for MockState {
    type Output = MockState;

    fn add(self, other: Self) -> Self {
        let res = self.0 + other.0;
        MockState(res)
    }
}

impl Sub for MockState {
    type Output = MockState;

    fn sub(self, other: Self) -> Self {
        let res = self.0 - other.0;
        MockState(res)
    }
}

impl MockState {
    pub fn into_raw(&self) -> u64 {
        self.0
    }
}

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
fn test_integration_transfer() {
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
