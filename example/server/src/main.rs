use std::collections::HashMap;
use std::io;
use sgx_types::sgx_enclave_id_t;
use anonify_host::prelude::init_enclave;
use actix_web::{
    client::Client,
    error::ErrorBadRequest,
    web::{self, BytesMut},
    App, Error, HttpResponse, HttpServer,
};
use handlers::*;

mod handlers;
mod api;

#[derive(Clone, Copy)]
pub struct EnclaveId(sgx_enclave_id_t);

impl EnclaveId {
    pub fn new() -> Self {
        let enclave_id = init_enclave();
        EnclaveId(enclave_id)
    }
}

fn main() -> io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    let endpoint = "127.0.0.1:8080";

    let enclave_id = EnclaveId::new();

    println!("Starting server at: {:?}", endpoint);
    HttpServer::new(move || {
        App::new()
            .data(enclave_id)
            .route("/deploy", web::post().to(handle_post_deploy))
            // .route("/transfer", web::post().to())
            // .route("/balance", web::get().to())
    })
    .bind(endpoint)?
    .run()
}
