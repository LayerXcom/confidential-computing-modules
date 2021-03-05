use anonify_eth_driver::{traits::*, Dispatcher, EventCache};
use frame_config::{ABI_PATH, BIN_PATH};
use sgx_types::sgx_enclave_id_t;
use std::env;

mod error;
pub mod handlers;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct Server<D: Deployer, S: Sender, W: Watcher> {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
    pub abi_path: String,
    pub bin_path: String,
    pub confirmations: usize,
    pub account_index: usize,
    pub password: Option<String>,
    pub sync_time: u64,
    pub dispatcher: Dispatcher<D, S, W>,
}

impl<D, S, W> Server<D, S, W>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    pub fn new(eid: sgx_enclave_id_t) -> Self {
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

        let cache = EventCache::default();
        let dispatcher = Dispatcher::<D, S, W>::new(eid, &eth_url, cache).unwrap();

        Server {
            eid,
            eth_url,
            abi_path: (&*ABI_PATH.to_str().unwrap()).to_string(),
            bin_path: (&*BIN_PATH.to_str().unwrap()).to_string(),
            confirmations,
            account_index,
            sync_time,
            password,
            dispatcher,
        }
    }
}
