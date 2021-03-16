use anonify_eth_driver::{traits::*, utils::get_account, Dispatcher, EventCache, Web3Http};
use frame_config::{ANONIFY_ABI_PATH, ANONIFY_BIN_PATH, FACTORY_ABI_PATH};
use sgx_types::sgx_enclave_id_t;
use std::env;
use web3::types::Address;

mod error;
pub mod handlers;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct Server<S: Sender, W: Watcher> {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
    pub abi_path: String,
    pub bin_path: String,
    pub confirmations: usize,
    pub account_index: usize,
    pub password: Option<String>,
    pub sync_time: u64,
    pub dispatcher: Dispatcher<S, W>,
}

impl<S, W> Server<S, W>
where
    S: Sender,
    W: Watcher,
{
    pub async fn new(eid: sgx_enclave_id_t, salt: [u8; 32]) -> Self {
        let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
        let account_index: usize = env::var("ACCOUNT_INDEX")
            .expect("ACCOUNT_INDEX is not set")
            .parse()
            .expect("Failed to parse ACCOUNT_INDEX to usize");
        let password: Option<String> = env::var("PASSWORD").ok();
        let confirmations: usize = env::var("CONFIRMATIONS")
            .expect("CONFIRMATIONS is not set")
            .parse()
            .expect("Failed to parse CONFIRMATIONS to usize");
        let sync_time: u64 = env::var("SYNC_BC_TIME")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .expect("Failed to parse SYNC_BC_TIME to u64");
        let factory_contract_address = Address::from_str(
            &env::var("FACTORY_CONTRACT_ADDRESS").expect("FACTORY_CONTRACT_ADDRESS is not set"),
        );

        let web3_conn = Web3Http::new(&eth_url).unwrap();
        let sender_address = get_account(&web3_conn, account_index, password.as_deref())
            .await
            .unwrap();

        let cache = EventCache::default();
        let dispatcher = Dispatcher::<S, W>::new(eid, &eth_url, cache)
            .set_anonify_contract_address(
                sender_address,
                &*FACTORY_ABI_PATH,
                factory_contract_address,
                &*ANONIFY_ABI_PATH,
            )
            .unwrap();

        Server {
            eid,
            eth_url,
            abi_path: (&*ANONIFY_ABI_PATH.to_str().unwrap()).to_string(),
            bin_path: (&*ANONIFY_BIN_PATH.to_str().unwrap()).to_string(),
            confirmations,
            account_index,
            sync_time,
            password,
            dispatcher,
        }
    }
}
