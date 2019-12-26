use std::{
    collections::HashMap,
    io,
    env,
};
use sgx_types::sgx_enclave_id_t;
use anonify_host::EnclaveDir;
use dotenv::dotenv;
use handlers::*;
use actix_web::{
    client::Client,
    error::ErrorBadRequest,
    web::{self, BytesMut},
    App, Error, HttpResponse, HttpServer,
};

mod handlers;

#[derive(Debug, Clone)]
pub struct Server {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
}

impl Server {
    pub fn new() -> Self {
        let enclave = EnclaveDir::new()
            .init_enclave(true)
            .expect("Failed to initialize enclave.");
        let eid = enclave.geteid();

        let eth_url = env::var("ETH_URL")
            .expect("ETH_URL is not set.");

        Server { eid, eth_url }
    }
}

fn main() -> io::Result<()> {
    env_logger::init();
    dotenv().ok();
    let endpoint = env::var("ANONIFY_URL")
        .expect("ANONIFY_URL is not set.");

    let server = Server::new();

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route("/deploy", web::post().to(handle_deploy))
            // .route("/transfer", web::post().to())
            // .route("/balance", web::get().to())
    })
    .bind(endpoint)?
    .run()
}
