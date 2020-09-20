#[macro_use]
extern crate lazy_static;
extern crate reqwest;

use actix_web::{web, App, HttpServer};
use anonify_eth_driver::{eth::*, traits::*, BlockNumDB, Dispatcher, EventDB};
use frame_host::EnclaveDir;
use handlers::*;
use sgx_types::sgx_enclave_id_t;
use std::{env, io, sync::Arc};

mod config;
mod handlers;
mod moneyforward;
mod sunabar;

#[derive(Debug)]
pub struct Server<D: Deployer, S: Sender, W: Watcher<WatcherDB = DB>, DB: BlockNumDB> {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
    pub abi_path: String,
    pub dispatcher: Dispatcher<D, S, W, DB>,
}

impl<D, S, W, DB> Server<D, S, W, DB>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB = DB>,
    DB: BlockNumDB,
{
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        let eth_url = env::var("ETH_URL").expect("ETH_URL is not set.");
        let abi_path =
            env::var("ANONYMOUS_ASSET_ABI_PATH").expect("ANONYMOUS_ASSET_ABI_PATH is not set.");
        let event_db = Arc::new(DB::new());
        let dispatcher = Dispatcher::<D, S, W, DB>::new(eid, &eth_url, event_db).unwrap();

        Server {
            eid,
            eth_url,
            abi_path,
            dispatcher,
        }
    }
}

fn main() -> io::Result<()> {
    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");
    env_logger::init();

    // Enclave must be initialized in main function.
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(Server::<
        EthDeployer,
        EthSender,
        EventWatcher<EventDB>,
        EventDB,
    >::new(eid));

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<
                    EthDeployer,
                    EthSender,
                    EventWatcher<EventDB>,
                    EventDB,
                >),
            )
            .route(
                "/api/v1/start_polling_moneyforward",
                web::post().to(handle_start_polling_moneyforward::<
                    EthDeployer,
                    EthSender,
                    EventWatcher<EventDB>,
                    EventDB,
                >),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::post().to(handle_start_sync_bc::<
                    EthDeployer,
                    EthSender,
                    EventWatcher<EventDB>,
                    EventDB,
                >),
            )
            .route(
                "/api/v1/set_notification",
                web::post().to(handle_set_notification::<
                    EthDeployer,
                    EthSender,
                    EventWatcher<EventDB>,
                    EventDB,
                >),
            )
            .route(
                "/api/v1/set_contract_addr",
                web::post().to(handle_set_contract_addr::<
                    EthDeployer,
                    EthSender,
                    EventWatcher<EventDB>,
                    EventDB,
                >),
            )
    })
    .bind(anonify_url)?
    .run()
}
