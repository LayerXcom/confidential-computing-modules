use actix_web::{web, App, HttpServer};
use anonify_eth_driver::eth::*;
use frame_host::EnclaveDir;
use state_runtime_node_server::{handlers::*, Server};
use std::{env, io, sync::Arc};

#[actix_web::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");
    let num_workers: usize = env::var("NUM_WORKERS")
        .unwrap_or_else(|_| "16".to_string())
        .parse()
        .expect("Failed to parse NUM_WORKERS");

    // Enclave must be initialized in main function.
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid));

    HttpServer::new(move || {
        App::new()
            .data(server.clone())
            .route(
                "/api/v1/deploy",
                web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/join_group",
                web::post().to(handle_join_group::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/update_mrenclave",
                web::post().to(handle_update_mrenclave::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::post().to(handle_send_command::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/state",
                web::get().to(handle_get_state::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/key_rotation",
                web::post().to(handle_key_rotation::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/start_sync_bc",
                web::get().to(handle_start_sync_bc::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/set_contract_address",
                web::get().to(handle_set_contract_address::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/register_notification",
                web::post()
                    .to(handle_register_notification::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/enclave_encryption_key",
                web::get().to(handle_enclave_encryption_key::<EthDeployer, EthSender, EventWatcher>),
            )
            .route(
                "/api/v1/register_report",
                web::post().to(handle_register_report::<EthDeployer, EthSender, EventWatcher>),
            )
    })
    .bind(anonify_url)?
    .workers(num_workers)
    .run()
    .await
}
