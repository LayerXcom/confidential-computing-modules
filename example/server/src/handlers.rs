use failure::Error;
use log::debug;
use ed25519_dalek::{PublicKey, Signature};
use anonify_host::prelude::*;
use sgx_types::sgx_enclave_id_t;

use actix_web::{
    web,
    HttpResponse,
};
use crate::{
    Server,
};

pub fn handle_deploy(
    server: web::Data<Server>,
    req: web::Json<api::deploy::post::Request>,
) -> Result<HttpResponse, Error> {
    debug!("Starting deploy a contract...");

    let sig = Signature::from_bytes(&req.sig).expect("Failed to get signature.");
    let pubkey = PublicKey::from_bytes(&req.pubkey).expect("Failed to get public key.");

    let access_right = AccessRight::new(sig, pubkey, req.nonce);

    let mut deployer = EthDeployer::new(server.eid, &server.eth_url)
        .expect("Failed to generate new deployer.");
    let deployer_addr = deployer.get_account(0)
        .expect("Failed to get a eth account.");
    let contract_addr = deployer.deploy(&deployer_addr, &access_right, req.total_supply)
        .expect("Failed to deploy a contract.");

    debug!("Contract address: {:?}", &contract_addr);

    Ok(HttpResponse::Ok().json(api::deploy::post::Response(contract_addr.to_fixed_bytes())))
}

pub fn handle_send(
    server: web::Data<Server>,
    req: web::Json<api::send::post::Request>,
) -> Result<HttpResponse, Error> {
    let sig = Signature::from_bytes(&req.sig).expect("Failed to get signature.");
    let pubkey = PublicKey::from_bytes(&req.pubkey).expect("Failed to get public key.");

    let access_right = AccessRight::new(sig, pubkey, req.nonce);
    let eth_sender = EthSender::new(
        server.eid,
        dotenv!("ETH_URL"),
        &req.contract_addr,
        dotenv!("ANONYMOUS_ASSET_ABI_PATH"),
    )
    .expect("Failed to initialize EthSender");

    let from_eth_addr = eth_sender.get_account(0).expect("Failed to get account.");

    let receipt = eth_sender.send_tx(
        &access_right,
        deployer_addr,
        &other_user_address,
        amount,
        from_eth_addr,
        gas
    )
    .expect("Failed to send a transaction.");

    unimplemented!();
}
