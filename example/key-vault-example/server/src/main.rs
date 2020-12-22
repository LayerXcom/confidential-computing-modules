use actix_web::{web, App, HttpServer};
use frame_host::{EnclaveDir, StorePathSecrets};
use handlers::*;
use key_vault_host::Dispatcher;
use sgx_types::sgx_enclave_id_t;
use std::{env, io, sync::Arc};

mod error;
mod handlers;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct Server {
    pub eid: sgx_enclave_id_t,
    pub dispatcher: Dispatcher,
}

impl Server {
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        let dispatcher = Dispatcher::new(eid).unwrap();
        Server {
            eid,
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

    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(Server::new(eid));

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route("/api/v1/start", web::post().to(handle_start))
            .route("/api/v1/stop", web::post().to(handle_stop))
    })
    .bind(anonify_url)?
    .workers(num_workers)
    .run()
    .await
}
