// use crate::*;
//
// use actix_web::{test, web, App};
// use integration_tests::set_env_vars;
//
// #[actix_rt::test]
// async fn test_backup_path_secret() {
//     set_env_vars();
//     set_server_env_vars();
//
//     // Enclave must be initialized in main function.
//     let enclave = EnclaveDir::new()
//         .init_enclave(true)
//         .expect("Failed to initialize enclave.");
//     let eid = enclave.geteid();
//     let server = Arc::new(Server::<EthDeployer, EthSender, EventWatcher>::new(eid));
//
//     let mut app = test::init_service(
//         App::new()
//             .data(server.clone())
//             .route("/api/v1/start", web::post().to(handle_start))
//             .route("/api/v1/stop", web::post().to(handle_stop)),
//     )
//     .await;
//
//     let req = test::TestRequest::post().uri("/api/v1/deploy").to_request();
//     let resp = test::call_service(&mut app, req).await;
//     assert!(resp.status().is_success(), "response: {:?}", resp);
//     let contract_addr: erc20_api::deploy::post::Response = test::read_body_json(resp).await;
//     println!("contract address: {:?}", contract_addr);
// }
