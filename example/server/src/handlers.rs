use failure::Error;
use log::debug;
use anonify_host::prelude::*;
use sgx_types::sgx_enclave_id_t;
use actix_web::{
    web,
    HttpResponse,
};
use crate::{
    Server,
    EVENT_DB,
};

pub const DEFAULT_SEND_GAS: u64 = 3_000_000;

pub fn handle_deploy(
    server: web::Data<Server>,
    req: web::Json<api::deploy::post::Request>,
) -> Result<HttpResponse, Error> {
    debug!("Starting deploy a contract...");

    let access_right = req.into_access_right()?;
    let mut deployer = EthDeployer::new(server.eid, &server.eth_url)?;
    let deployer_addr = deployer.get_account(0)?;
    let contract_addr = deployer.deploy(&deployer_addr, &access_right, req.total_supply)?;

    debug!("Contract address: {:?}", &contract_addr);

    Ok(HttpResponse::Ok().json(api::deploy::post::Response(contract_addr)))
}

pub fn handle_send(
    server: web::Data<Server>,
    req: web::Json<api::send::post::Request>,
) -> Result<HttpResponse, Error> {
    let access_right = req.into_access_right()?;
    let eth_sender = EthSender::new(
        server.eid,
        &server.eth_url,
        &req.contract_addr,
        dotenv!("ANONYMOUS_ASSET_ABI_PATH"),
    )?;
    let from_eth_addr = eth_sender.get_account(0)?;

    let receipt = eth_sender.send_tx(
        &access_right,
        &req.target,
        req.amount,
        from_eth_addr,
        DEFAULT_SEND_GAS,
    )?;

    Ok(HttpResponse::Ok().json(api::send::post::Response(receipt)))
}

/// Fetch events from blockchain nodes manually, and then get state from enclave.
pub fn handle_state(
    server: web::Data<Server>,
    req: web::Json<api::state::get::Request>,
) -> Result<HttpResponse, Error> {
    let ev_watcher = EventWatcher::new(
        &server.eth_url,
        dotenv!("ANONYMOUS_ASSET_ABI_PATH"),
        &req.contract_addr,
        EVENT_DB,
    )?;
    ev_watcher.block_on_init(server.eid)?;
    ev_watcher.block_on_send(server.eid)?;

    let access_right = req.into_access_right()?;
    let state = get_state_by_access_right(&access_right, server.eid)?;

    Ok(HttpResponse::Ok().json(api::state::get::Response(state)))
}
