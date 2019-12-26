#![feature(proc_macro_hygiene)]
#![feature(decl_macro)]
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate lazy_static;

use std::{
    collections::HashMap,
    io,
    env,
};
use sgx_types::sgx_enclave_id_t;
use anonify_host::EnclaveDir;
use dotenv::dotenv;
use handlers::*;

mod handlers;

pub const ETH_URL: &'static str = "http://172.18.0.2:8545";

lazy_static! {
    pub static ref ENCLAVE_ID: sgx_enclave_id_t = {
        let enclave = EnclaveDir::new()
            .init_enclave(true)
            .expect("Failed to initialize enclave.");
        enclave.geteid()
    };

    // pub static ref ETH_URL: &'static str = {
    //     let eth_url = env::var("ETH_URL").expect("ETH_URL is not set.");
    //     &eth_url
    // };
}

#[derive(Debug)]
pub struct Enclacve {
    pub eid: sgx_enclave_id_t,
}

fn main() {
    env_logger::init();
    dotenv().ok();
    let endpoint = env::var("ANONIFY_URL")
        .expect("ANONIFY_URL is not set.");

    let enclave = EnclaveDir::new()
            .init_enclave(true)
            .expect("Failed to initialize enclave.");
    let eid = enclave.geteid();

    rocket::ignite()
        .manage(Enclacve { eid })
        .mount("/", routes![handle_deploy])
        .launch();
}
