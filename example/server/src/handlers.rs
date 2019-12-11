use actix_web::{
    web,
    HttpResponse,
};
use crate::{
    api,
    Server,
};
use failure::Error;
use anonify_host::prelude::anonify_deploy;

pub fn handle_post_deploy(
    server: web::Data<Server>,
    req: web::Json<api::deploy::post::Request>,
) -> Result<HttpResponse, Error> {
    let contract_addr = anonify_deploy(
        server.enclave_id,
        &req.sig[..],
        &req.pubkey[..],
        &req.nonce[..],
        req.total_supply,
        &server.eth_url,
    ).expect("Failed to deploy contract.");

    Ok(HttpResponse::Ok().json(api::deploy::post::Response(contract_addr)))
}

pub fn handle_post_transfer(

) {
    unimplemented!();
}

pub fn handle_get_balance() {
    unimplemented!();
}
