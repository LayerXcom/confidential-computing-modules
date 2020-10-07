use crate::*;
use actix_web::{test, web, App};
use integration_tests::set_env_vars;

#[actix_rt::test]
async fn test_deploy_post() {
    set_env_vars();
    set_server_env_vars();

    // Enclave must be initialized in main function.
    let enclave = EnclaveDir::new()
        .init_enclave(true)
        .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();
    let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid));

    let mut app = test::init_service(App::new().data(server.clone()).route(
        "/api/v1/deploy",
        web::post().to(handle_deploy::<EthDeployer, EthSender, EventWatcher>),
    ))
    .await;

    let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
    let resp = test::call_service(&mut app, req).await;
    println!("response: {:?}", resp);
}

fn set_server_env_vars() {
    env::set_var("ETH_URL", "http://172.28.0.2:8545");
    env::set_var("ABI_PATH", "../../../contract-build/Anonify.abi");
    env::set_var("BIN_PATH", "../../../contract-build/Anonify.bin");
    env::set_var("CONFIRMATIONS", "0");
    env::set_var("ACCOUNT_INDEX", "0");
    env::set_var("PASSWORD", "anonify0101");
}
