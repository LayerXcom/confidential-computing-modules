use std::{sync::Arc, io, env};
use anonify_host::EnclaveDir;
use anonify_bc_connector::{
    EventDB,
    traits::*,
    eth::*,
};
use dx_server::handlers::*;
use actix_web::{web, App, HttpServer};

fn main() -> io::Result<()> {
    env_logger::init();
    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");

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

