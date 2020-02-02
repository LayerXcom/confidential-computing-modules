#[macro_use]
extern crate dotenv_codegen;
#[macro_use]
extern crate lazy_static;
use std::{
    collections::HashMap,
    io,
    env,
    sync::Arc,
};
use sgx_types::sgx_enclave_id_t;
use anonify_host::{
    EnclaveDir,
    transaction::{
        Dispatcher, EventDB, BlockNumDB, traits::*,
        eth::{EthDeployer, EthSender, EventWatcher},
    },
};
use handlers::*;
use actix_web::{
    client::Client,
    error::ErrorBadRequest,
    web::{self, BytesMut},
    App, Error, HttpResponse, HttpServer,
};

mod handlers;

lazy_static! {
    pub static ref EVENT_DB: EventDB = { EventDB::new() };
}

#[derive(Debug)]
pub struct Server<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
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
        let eth_url = dotenv!("ETH_URL").to_string();

        let event_db = Arc::new(DB::new());
        let dispatcher = Dispatcher::<D,S,W,DB>::new_with_deployer(eid, &eth_url, event_db).unwrap();
        let dispatcher = Arc::new(dispatcher);

        Server {
            eid,
            eth_url,
            dispatcher
        }
    }
}

fn main() -> io::Result<()> {
    env_logger::init();
    dotenv::from_filename(".env.template").ok();

    // Enclave must be initialized in main function.
    let enclave = EnclaveDir::new()
            .init_enclave(true)
            .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid));

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route("/deploy", web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/send", web::post().to(handle_send::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
            .route("/state", web::get().to(handle_state::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
    })
    .bind(dotenv!("ANONIFY_URL"))?
    .run()
}
