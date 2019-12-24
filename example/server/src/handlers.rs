use actix_web::{
    web,
    HttpResponse,
};
use crate::{
    Server,
};
use failure::Error;
use log::debug;
use anonify_host::prelude::*;

pub fn handle_post_deploy(
    server: web::Data<Server>,
    req: web::Json<api::deploy::post::Request>,
) -> Result<HttpResponse, Error> {
    debug!("Starting deploy a contract...");

    let access_right = AccessRight::new(req.sig, req.pubkey, req. nonce);

    let mut deployer = EthDeployer::new(server.eid, &server.eth_url)
        .expect("Failed to generate new deployer.");
    let deployer_addr = deployer.get_account(0)
        .expect("Failed to get a eth account.");
    let contract_addr = deployer.deploy(&deployer_addr, &access_right, req.total_supply)
        .expect("Failed to deploy a contract.");

    debug!("Contract address: {:?}", &contract_addr);

    Ok(HttpResponse::Ok().json(api::deploy::post::Response(contract_addr.to_fixed_bytes())))
}

pub fn handle_post_transfer(
    server: web::Data<Server>,
    req: web::Json<api::send::post::Request>,
) {

    unimplemented!();
}

pub fn handle_get_balance() {
    unimplemented!();
}
