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
    // let client = MFClient::new();
    // let resp = client.get_invoices().unwrap();
    //
    // let invoces = Billing::from_response(resp);


    // let = state_id: u64 = ; TODO:
    // let recipient: UserAddress = ; TODO:
    // let contract_addr = env::var("CONTRACT_ADDR").unwrap_or_else(|_| String::default());
    // let rng = &mut OsRng;
    // let req = api::send_invoice::post::Request::new(&keypair, state_id, recipient, body, contract_addr, rng);
    // let res = Client::new()
    //     .post(&format!("{}/api/v1/send_invoice", &anonify_url))
    //     .json(&req)
    //     .send()?
    //     .text()?;

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
    })
        .bind(anonify_url)?
        .run()
}

