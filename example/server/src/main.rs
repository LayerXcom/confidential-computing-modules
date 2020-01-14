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
use anonify_host::{EnclaveDir, prelude::EventDB};
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
pub struct Server {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
    pub event_db: Arc<EventDB>,
}

impl Server {
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        let eth_url = dotenv!("ETH_URL").to_string();
        let event_db = Arc::new(EventDB::new());

        Server { eid, eth_url, event_db }
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
    let server = Arc::new(Server::new(eid));

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route("/deploy", web::post().to(handle_deploy))
            .route("/send", web::post().to(handle_send))
            .route("/state", web::get().to(handle_state))
    })
    .bind(dotenv!("ANONIFY_URL"))?
    .run()
}
