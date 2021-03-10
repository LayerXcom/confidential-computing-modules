use actix_web::{web, App, HttpServer};
use frame_host::EnclaveDir;
use key_vault_node_server::{handlers::*, Server};
use std::{env, io, sync::Arc};

#[actix_web::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    let my_node_url = env::var("MY_NODE_URL").expect("MY_NODE_URL is not set.");
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
    .bind(my_node_url)?
    .workers(num_workers)
    .run()
    .await
}
