#[macro_use]
extern crate lazy_static;
use anonify_eth_driver::dispatcher::*;
use ethabi::Contract as ContractABI;
use frame_config::ANONIFY_ABI_PATH;
use frame_sodium::SodiumPubKey;
use once_cell::sync::Lazy;
use std::{env, fs::File, io::BufReader};
use web3::{
    contract::{Contract, Options},
    transports::Http,
    types::Address,
    Web3,
};

mod enclave_key;
mod treekem;

#[cfg(test)]
const ACCOUNT_INDEX: usize = 0;
#[cfg(test)]
const PASSWORD: &str = "anonify0101";
#[cfg(test)]
const CONFIRMATIONS: usize = 0;

pub static ETH_URL: Lazy<String> =
    Lazy::new(|| env::var("ETH_URL").unwrap_or("http://172.16.0.2:8545".to_string()));

pub static CHAIN_ID: Lazy<u64> = Lazy::new(|| env::var("CHAIN_ID")
    .unwrap_or_else(|_| "1337".to_string())
    .parse::<u64>()
    .unwrap()
);

pub static SIGNER_PRI_KEY: Lazy<String> = Lazy::new(|| env::var("SIGNER_PRI_KEY")
        .unwrap_or("5c7a050c7b0e3a6896e9667a6dff3a6b389c665aaed218c352071890c05520ee"
        .to_string()
    )
);
pub async fn get_enclave_encryption_key(
    contract_addr: Address,
    dispatcher: &Dispatcher,
) -> SodiumPubKey {
    let enclave_encryption_key = dispatcher.get_enclave_encryption_key().unwrap();
    let transport = Http::new(&*ETH_URL).unwrap();
    let web3 = Web3::new(transport);
    let web3_conn = web3.eth();

    let f = File::open(&*ANONIFY_ABI_PATH).unwrap();
    let abi = ContractABI::load(BufReader::new(f)).unwrap();

    let query_enclave_encryption_key: Vec<u8> = Contract::new(web3_conn, contract_addr, abi)
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
    env::set_var("ENCLAVE_PKG_NAME", "erc20");
    env::set_var("BACKUP", "disable");
}

pub fn set_env_vars_for_treekem() {
    env::set_var("ANONIFY_ABI_PATH", "contract-build/AnonifyWithTreeKem.abi");
    env::set_var("ANONIFY_BIN_PATH", "contract-build/AnonifyWithTreeKem.bin");
}
