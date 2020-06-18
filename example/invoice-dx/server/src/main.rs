#[macro_use]
extern crate lazy_static;
extern crate reqwest;

use std::{sync::Arc, io, env};
use actix_web::{web, App, HttpServer};
use sgx_types::sgx_enclave_id_t;

use anonify_host::{EnclaveDir, Dispatcher};
use anonify_bc_connector::{
    EventDB,
    BlockNumDB,
    traits::*,
    eth::*,
};

use handlers::*;

mod moneyforward;
mod sunabar;
mod handlers;
mod config;

#[derive(Debug)]
pub struct Server<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
    pub abi_path: String,
    pub dispatcher: Dispatcher<D, S, W, DB>,
}

impl<D, S, W, DB> Server<D, S, W, DB>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        let eth_url = env::var("ETH_URL").expect("ETH_URL is not set.");
        let abi_path = env::var("ANONYMOUS_ASSET_ABI_PATH").expect("ANONYMOUS_ASSET_ABI_PATH is not set.");
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
    let server = Arc::new(
        Server::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid)
    );

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route("/api/v1/send_invoice", web::post().to(handle_send_invoice::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/api/v1/start_polling_moneyforward", web::post().to(handle_start_polling_moneyforward))
            .route("/api/v1/handle_start_sync_bc", web::post().to(handle_start_sync_bc))
    })
        .bind(anonify_url)?
        .run()
}

