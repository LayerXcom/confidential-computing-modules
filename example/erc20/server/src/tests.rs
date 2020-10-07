use crate::*;
use actix_web::{test, web, App};
use integration_tests::set_env_vars;

#[actix_rt::test]
async fn test_deploy_post() {
    set_env_vars();

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
