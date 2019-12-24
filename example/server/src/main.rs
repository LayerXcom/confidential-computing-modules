use std::{
    collections::HashMap,
    io,
    env,
};
use sgx_types::sgx_enclave_id_t;
use anonify_host::prelude::init_enclave;
use dotenv::dotenv;
use actix_web::{
    client::Client,
    error::ErrorBadRequest,
    web::{self, BytesMut},
    App, Error, HttpResponse, HttpServer,
};
use handlers::*;

mod handlers;

#[derive(Clone)]
pub struct Server {
    eid: sgx_enclave_id_t,
    eth_url: String,
}

impl Server {
    pub fn new() -> Self {
        let eid = init_enclave();
        println!("eid: {:?}", eid);

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

    println!("Starting server at: {:?}", endpoint);
    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route("/deploy", web::post().to(handle_post_deploy))
            // .route("/transfer", web::post().to())
            // .route("/balance", web::get().to())
    })
    .bind(endpoint)?
    .run()
}
