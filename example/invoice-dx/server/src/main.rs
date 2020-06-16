use std::env;
// use anonify_host::EnclaveDir;

fn main() {
    // let client = MFClient::new();
    // let resp = client.get_invoices().unwrap();
    //
    // let invoces = Billing::from_response(resp);


    env_logger::init();
    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");

    // Enclave must be initialized in main function.
    // let enclave = EnclaveDir::new()
    //         .init_enclave(true)
    //         .expect("Failed to initialize enclave.");
    // let eid = enclave.geteid();
    // let server = Arc::new(
    //     Server::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid)
    // );
    //
    // HttpServer::new(move || {
    //     App::new()
    //         .data(server.clone())
    //         .route("/api/v1/notify", web::post().to(handle_notify::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>))
    // })
    // .bind(anonify_url)?
    // .run()


}

