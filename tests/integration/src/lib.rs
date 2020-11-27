#[macro_use]
extern crate lazy_static;
use anonify_eth_driver::{dispatcher::*, eth::*, EventCache};
use codec::{Decode, Encode};
use erc20_state_transition::{
    approve, burn, construct, mint, transfer, transfer_from, CallName, MemName, CIPHERTEXT_SIZE,
};
use ethabi::Contract as ContractABI;
use frame_common::{
    crypto::{AccountId, Ed25519ChallengeResponse, COMMON_ACCESS_POLICY},
    traits::*,
};
use frame_host::EnclaveDir;
use frame_runtime::primitives::{Approved, U64};
use sodiumoxide::crypto::box_::{self, PublicKey as SodiumPublicKey};
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

lazy_static! {
    pub static ref ENV_LOGGER_INIT: () = env_logger::init();
}

pub async fn get_encrypting_key(
    contract_addr: &str,
    dispatcher: &Dispatcher<EthDeployer, EthSender, EventWatcher>,
) -> SodiumPublicKey {
    let encrypting_key = dispatcher.get_encrypting_key().unwrap();
    let transport = Http::new(ETH_URL).unwrap();
    let web3 = Web3::new(transport);
    let web3_conn = web3.eth();

    let address = Address::from_str(contract_addr).unwrap();
    let f = File::open(ABI_PATH).unwrap();
    let abi = ContractABI::load(BufReader::new(f)).unwrap();

    let query_encrypting_key: Vec<u8> = Contract::new(web3_conn, address, abi)
        .query(
            "getEncryptingKey",
            encrypting_key.0.to_vec(),
            None,
            Options::default(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        encrypting_key,
        SodiumPublicKey::from_slice(&mut &query_encrypting_key[..]).unwrap()
    );
    encrypting_key
}

#[actix_rt::test]
async fn test_integration_eth_construct() {
    set_env_vars();
    let enclave = EnclaveDir::new().init_enclave(true).unwrap();
    let eid = enclave.geteid();
    let my_access_policy = Ed25519ChallengeResponse::new_from_rng().unwrap();

    let gas = 5_000_000;
    let cache = EventCache::default();
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    let (my_encrypting_pubkey, my_encrypting_privkey) = box_::gen_keypair();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
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
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let pubkey = get_encrypting_key(&contract_addr, &dispatcher).await;
    let init_cmd = construct { total_supply };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(init_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Get state from enclave
    let owner_account_id = dispatcher
        .get_state::<AccountId, _, CallName>(COMMON_ACCESS_POLICY.clone(), "owner")
        .unwrap();
    let my_balance = dispatcher
        .get_state::<U64, _, CallName>(my_access_policy.clone(), "balance_of")
        .unwrap();
    let actual_total_supply = dispatcher
        .get_state::<U64, _, CallName>(COMMON_ACCESS_POLICY.clone(), "total_supply")
        .unwrap();
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
    let cache = EventCache::default();
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    let (my_encrypting_pubkey, my_encrypting_privkey) = box_::gen_keypair();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
    let (contract_addr, _) = dispatcher
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

    // Get handshake from contract
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Init state
    let pubkey = get_encrypting_key(&contract_addr, &dispatcher).await;
    let total_supply = U64::from_raw(100);
    let init_cmd = construct { total_supply };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(init_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    let updated_state = dispatcher.fetch_events::<U64>().await.unwrap().unwrap();

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
    let transfer_cmd = transfer { amount, recipient };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(transfer_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "transfer",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    let updated_state = dispatcher.fetch_events::<U64>().await.unwrap().unwrap();

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
    let cache = EventCache::default();
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    let (my_encrypting_pubkey, my_encrypting_privkey) = box_::gen_keypair();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
    let (contract_addr, _) = dispatcher
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

    // Get handshake from contract
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let pubkey = get_encrypting_key(&contract_addr, &dispatcher).await;
    let init_cmd = construct { total_supply };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(init_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Get state from enclave
    let my_state = dispatcher
        .get_state::<U64, _, CallName>(my_access_policy.clone(), "balance_of")
        .unwrap();
    let other_state = dispatcher
        .get_state::<U64, _, CallName>(other_access_policy.clone(), "balance_of")
        .unwrap();
    let third_state = dispatcher
        .get_state::<U64, _, CallName>(third_access_policy.clone(), "balance_of")
        .unwrap();
    assert_eq!(my_state, total_supply);
    assert_eq!(other_state, U64::zero());
    assert_eq!(third_state, U64::zero());

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let recipient = other_access_policy.into_account_id();
    let transfer_cmd = transfer { amount, recipient };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(transfer_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "transfer",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Check the updated states
    let my_updated_state = dispatcher
        .get_state::<U64, _, CallName>(my_access_policy, "balance_of")
        .unwrap();
    let other_updated_state = dispatcher
        .get_state::<U64, _, CallName>(other_access_policy, "balance_of")
        .unwrap();
    let third_updated_state = dispatcher
        .get_state::<U64, _, CallName>(third_access_policy, "balance_of")
        .unwrap();

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
    let cache = EventCache::default();
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    let (my_encrypting_pubkey, my_encrypting_privkey) = box_::gen_keypair();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
    let (contract_addr, _) = dispatcher
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

    // Get handshake from contract
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Send handshake
    let (receipt, _) = dispatcher
        .handshake(deployer_addr.clone(), gas)
        .await
        .unwrap();
    println!("handshake receipt: {:?}", receipt);

    // Get handshake from contract
    dispatcher.fetch_events::<U64>().await.unwrap();

    // init state
    let total_supply = U64::from_raw(100);
    let pubkey = get_encrypting_key(&contract_addr, &dispatcher).await;
    let init_cmd = construct { total_supply };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(init_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();
    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Get state from enclave
    let my_state = dispatcher
        .get_state::<U64, _, CallName>(my_access_policy, "balance_of")
        .unwrap();
    let other_state = dispatcher
        .get_state::<U64, _, CallName>(other_access_policy, "balance_of")
        .unwrap();
    let third_state = dispatcher
        .get_state::<U64, _, CallName>(third_access_policy, "balance_of")
        .unwrap();
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
    let cache = EventCache::default();
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    let (my_encrypting_pubkey, my_encrypting_privkey) = box_::gen_keypair();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
    let (contract_addr, _) = dispatcher
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

    // Get handshake from contract
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let pubkey = get_encrypting_key(&contract_addr, &dispatcher).await;
    let init_cmd = construct { total_supply };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(init_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Get state from enclave
    let my_state = dispatcher
        .get_state::<Approved, _, CallName>(my_access_policy.clone(), "approved")
        .unwrap();
    let other_state = dispatcher
        .get_state::<Approved, _, CallName>(other_access_policy.clone(), "approved")
        .unwrap();
    assert_eq!(my_state, Approved::default());
    assert_eq!(other_state, Approved::default());

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let spender = other_access_policy.into_account_id();
    let approve_state = approve { amount, spender };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(approve_state.encode(), &nonce, &pubkey, &my_encrypting_privkey);

    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "approve",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Check the updated states
    let my_state = dispatcher
        .get_state::<Approved, _, CallName>(my_access_policy, "approved")
        .unwrap();
    let other_state = dispatcher
        .get_state::<Approved, _, CallName>(other_access_policy, "approved")
        .unwrap();
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
    let cache = EventCache::default();
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    let (my_encrypting_pubkey, my_encrypting_privkey) = box_::gen_keypair();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
    let (contract_addr, _) = dispatcher
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

    // Get handshake from contract
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let pubkey = get_encrypting_key(&contract_addr, &dispatcher).await;
    let init_cmd = construct { total_supply };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(init_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Get initial state from enclave
    let my_state_balance = dispatcher
        .get_state::<U64, _, CallName>(my_access_policy.clone(), "balance_of")
        .unwrap();
    let other_state_balance = dispatcher
        .get_state::<U64, _, CallName>(other_access_policy.clone(), "balance_of")
        .unwrap();
    let third_state_balance = dispatcher
        .get_state::<U64, _, CallName>(third_access_policy.clone(), "balance_of")
        .unwrap();
    assert_eq!(my_state_balance, U64::from_raw(100));
    assert_eq!(other_state_balance, U64::zero());
    assert_eq!(third_state_balance, U64::zero());

    let my_state_approved = dispatcher
        .get_state::<Approved, _, CallName>(my_access_policy.clone(), "approved")
        .unwrap();
    let other_state_approved = dispatcher
        .get_state::<Approved, _, CallName>(other_access_policy.clone(), "approved")
        .unwrap();
    let third_state_approved = dispatcher
        .get_state::<Approved, _, CallName>(third_access_policy.clone(), "approved")
        .unwrap();
    assert_eq!(my_state_approved, Approved::default());
    assert_eq!(other_state_approved, Approved::default());
    assert_eq!(third_state_approved, Approved::default());

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let spender = other_access_policy.into_account_id();
    let approve_state = approve { amount, spender };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(approve_state.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "approve",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Check the updated states
    let my_state_balance = dispatcher
        .get_state::<U64, _, CallName>(my_access_policy.clone(), "balance_of")
        .unwrap();
    let other_state_balance = dispatcher
        .get_state::<U64, _, CallName>(other_access_policy.clone(), "balance_of")
        .unwrap();
    let third_state_balance = dispatcher
        .get_state::<U64, _, CallName>(third_access_policy.clone(), "balance_of")
        .unwrap();
    assert_eq!(my_state_balance, U64::from_raw(100));
    assert_eq!(other_state_balance, U64::zero());
    assert_eq!(third_state_balance, U64::zero());

    let my_state_approved = dispatcher
        .get_state::<Approved, _, CallName>(my_access_policy.clone(), "approved")
        .unwrap();
    let other_state_approved = dispatcher
        .get_state::<Approved, _, CallName>(other_access_policy.clone(), "approved")
        .unwrap();
    let third_state_approved = dispatcher
        .get_state::<Approved, _, CallName>(third_access_policy.clone(), "approved")
        .unwrap();
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
    let transfer_from_cmd = transfer_from {
        owner,
        recipient,
        amount,
    };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(transfer_from_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            other_access_policy.clone(),
            encrypted_command,
            "transfer_from",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Check the final states
    let my_state_balance = dispatcher
        .get_state::<U64, _, CallName>(my_access_policy.clone(), "balance_of")
        .unwrap();
    let other_state_balance = dispatcher
        .get_state::<U64, _, CallName>(other_access_policy.clone(), "balance_of")
        .unwrap();
    let third_state_balance = dispatcher
        .get_state::<U64, _, CallName>(third_access_policy.clone(), "balance_of")
        .unwrap();
    assert_eq!(my_state_balance, U64::from_raw(80));
    assert_eq!(other_state_balance, U64::zero());
    assert_eq!(third_state_balance, U64::from_raw(20));

    let my_state_approved = dispatcher
        .get_state::<Approved, _, CallName>(my_access_policy, "approved")
        .unwrap();
    let other_state_approved = dispatcher
        .get_state::<Approved, _, CallName>(other_access_policy, "approved")
        .unwrap();
    let third_state_approved = dispatcher
        .get_state::<Approved, _, CallName>(third_access_policy, "approved")
        .unwrap();
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
    let cache = EventCache::default();
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    let (my_encrypting_pubkey, my_encrypting_privkey) = box_::gen_keypair();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
    let (contract_addr, _) = dispatcher
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

    // Get handshake from contract
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let pubkey = get_encrypting_key(&contract_addr, &dispatcher).await;
    let init_cmd = construct { total_supply };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(init_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.fetch_events::<U64>().await.unwrap();

    // transit state
    let amount = U64::from_raw(50);
    let recipient = other_access_policy.into_account_id();
    let minting_state = mint { amount, recipient };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(minting_state.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "mint",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();

    println!("minted state receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Check the final states
    let actual_total_supply = dispatcher
        .get_state::<U64, _, CallName>(COMMON_ACCESS_POLICY.clone(), "total_supply")
        .unwrap();
    let owner_balance = dispatcher
        .get_state::<U64, _, CallName>(my_access_policy, "balance_of")
        .unwrap();
    let other_balance = dispatcher
        .get_state::<U64, _, CallName>(other_access_policy, "balance_of")
        .unwrap();
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
    let cache = EventCache::default();
    let dispatcher =
        Dispatcher::<EthDeployer, EthSender, EventWatcher>::new(eid, ETH_URL, cache).unwrap();

    let (my_encrypting_pubkey, my_encrypting_privkey) = box_::gen_keypair();

    // Deploy
    let deployer_addr = dispatcher
        .get_account(ACCOUNT_INDEX, PASSWORD)
        .await
        .unwrap();
    let (contract_addr, _) = dispatcher
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

    // Get handshake from contract
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Init state
    let total_supply = U64::from_raw(100);
    let pubkey = get_encrypting_key(&contract_addr, &dispatcher).await;
    let init_cmd = construct { total_supply };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(init_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "construct",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();

    println!("init state receipt: {:?}", receipt);

    // Get logs from contract and update state inside enclave.
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Send a transaction to contract
    let amount = U64::from_raw(30);
    let recipient = other_access_policy.into_account_id();
    let transfer_cmd = transfer { amount, recipient };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(transfer_cmd.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            my_access_policy.clone(),
            encrypted_command,
            "transfer",
            deployer_addr.clone(),
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Send a transaction to contract
    let amount = U64::from_raw(20);
    let burn_state = burn { amount };
    let nonce = box_::gen_nonce();
    let encrypted_command = box_::seal(burn_state.encode(), &nonce, &pubkey, &my_encrypting_privkey);
    let receipt = dispatcher
        .send_command::<CallName, _>(
            other_access_policy.clone(),
            encrypted_command,
            "burn",
            deployer_addr,
            gas,
        )
        .await
        .unwrap();
    println!("receipt: {:?}", receipt);

    // Update state inside enclave
    dispatcher.fetch_events::<U64>().await.unwrap();

    // Check the final states
    let actual_total_supply = dispatcher
        .get_state::<U64, _, CallName>(COMMON_ACCESS_POLICY.clone(), "total_supply")
        .unwrap();
    let owner_balance = dispatcher
        .get_state::<U64, _, CallName>(my_access_policy, "balance_of")
        .unwrap();
    let other_balance = dispatcher
        .get_state::<U64, _, CallName>(other_access_policy, "balance_of")
        .unwrap();
    assert_eq!(actual_total_supply, U64::from_raw(80)); // 100 - 20(burn)
    assert_eq!(owner_balance, U64::from_raw(70)); // 100 - 30(transfer)
    assert_eq!(other_balance, U64::from_raw(10)); // 30 - 20(burn)
}

pub fn set_env_vars() {
    *ENV_LOGGER_INIT;
    env::set_var("RUST_LOG", "DEBUG");
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
