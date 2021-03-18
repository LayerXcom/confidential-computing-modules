use actix_web::{web, App, HttpServer};
use frame_host::EnclaveDir;
use state_runtime_node_server::{handlers::*, Server};
use std::{env, io, sync::Arc};

#[actix_web::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    let my_node_url = env::var("MY_NODE_URL").expect("MY_NODE_URL is not set.");
    let num_workers: usize = env::var("NUM_WORKERS")
        .unwrap_or_else(|_| "16".to_string())
        .parse()
        .expect("Failed to parse NUM_WORKERS");

    // Enclave must be initialized in main function.
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Server::new(eid).await.run().await;
    let server = Arc::new(server);

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/update_mrenclave",
                web::post().to(handle_update_mrenclave),
            )
            .route("/api/v1/state", web::post().to(handle_send_command))
            .route("/api/v1/state", web::get().to(handle_get_state))
            .route(
                "/api/v1/user_counter",
                web::get().to(handle_get_user_counter),
            )
            .route("/api/v1/key_rotation", web::post().to(handle_key_rotation))
            .route(
                "/api/v1/register_notification",
                web::post().to(handle_register_notification),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key),
            )
            .route(
                "/api/v1/register_report",
                web::post().to(handle_register_report),
            )
    })
    .bind(my_node_url)?
    .workers(num_workers)
    .run()
    .await
}
