use actix_web::{web, App, HttpServer};
use anonify_eth_driver::{eth::*, traits::*, Dispatcher, EventCache};
use frame_host::{EnclaveDir, StorePathSecrets};
use handlers::*;
use sgx_types::sgx_enclave_id_t;
use std::{env, io, sync::Arc};

mod error;
mod handlers;
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
    pub password: String,
    pub sync_time: u64,
    pub store_path_secrets: StorePathSecrets,
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
        let abi_path = env::var("ABI_PATH").expect("ABI_PATH is not set");
        let bin_path = env::var("BIN_PATH").expect("BIN_PATH is not set");
        let account_index: usize = env::var("ACCOUNT_INDEX")
            .expect("ACCOUNT_INDEX is not set")
            .parse()
            .expect("Failed to parse ACCOUNT_INDEX to usize");
        let password = env::var("PASSWORD").expect("PASSWORD is not set");
        let confirmations: usize = env::var("CONFIRMATIONS")
            .expect("CONFIRMATIONS is not set")
            .parse()
            .expect("Failed to parse ACCOUNT_INDEX to usize");
        let sync_time: u64 = env::var("SYNC_BC_TIME")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .expect("Failed to parse SYNC_BC_TIME to u64");

        let store_path_secrets = StorePathSecrets::new();
        let cache = EventCache::default();
        let dispatcher = Dispatcher::<D, S, W>::new(eid, &eth_url, cache).unwrap();

        Server {
            eid,
            eth_url,
            abi_path,
            bin_path,
            confirmations,
            account_index,
            sync_time,
            password,
            store_path_secrets,
            dispatcher,
        }
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");
    let num_workers: usize = env::var("NUM_WORKERS")
        .unwrap_or_else(|_| "16".to_string())
        .parse()
        .expect("Failed to parse NUM_WORKERS");

    // Enclave must be initialized in main function.
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid));

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/update_mrenclave",
                web::post().to(handle_update_mrenclave::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/init_state",
                web::post().to(handle_init_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/transfer",
                web::post().to(handle_transfer::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/key_rotation",
                web::post().to(handle_key_rotation::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/approve",
                web::post().to(handle_approve::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/transfer_from",
                web::post().to(handle_transfer_from::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/mint",
                web::post().to(handle_mint::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/burn",
                web::post().to(handle_burn::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/allowance",
                web::get().to(handle_allowance::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/balance_of",
                web::get().to(handle_balance_of::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_addr",
                web::get().to(handle_set_contract_addr::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/register_notification",
                web::post()
                    .to(handle_register_notification::<EthDeployer, EthSender, EventWatcher>),
            )
    })
    .bind(anonify_url)?
    .workers(num_workers)
    .run()
    .await
}
