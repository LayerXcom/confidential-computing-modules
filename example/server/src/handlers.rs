use actix_web::{
    web,
    HttpResponse,
};
use crate::{
    Server,
    ENCLAVE_ID
};
use failure::Error;
use log::debug;
use anonify_host::prelude::anonify_deploy;

pub fn handle_post_deploy(
    server: web::Data<Server>,
    req: web::Json<api::deploy::post::Request>,
) -> Result<HttpResponse, Error> {
    debug!("Starting deploy a contract...");

    let contract_addr = anonify_deploy(
        *ENCLAVE_ID,
        &req.sig[..],
        &req.pubkey[..],
        &req.nonce[..],
        req.total_supply,
        &server.eth_url,
    ).expect("Failed to deploy contract.");

    debug!("Contract address: {:?}", &contract_addr);

    Ok(HttpResponse::Ok().json(api::deploy::post::Response(contract_addr)))
}

pub fn handle_post_transfer(

) {
    unimplemented!();
}

pub fn handle_get_balance() {
    unimplemented!();
}
