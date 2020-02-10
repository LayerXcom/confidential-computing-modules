use std::sync::Arc;
use failure::Error;
use log::debug;
use anonify_host::transaction::{
    BlockNumDB, traits::*,
    utils::get_state_by_access_right,
};
use anonymous_asset::api;
use anonify_common::{stf::Value, State};
use actix_web::{
    web,
    HttpResponse,
};
use crate::Server;

const DEFAULT_SEND_GAS: u64 = 3_000_000;

pub fn handle_deploy<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<api::deploy::post::Request>,
) -> Result<HttpResponse, Error>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB=DB>,
    DB: BlockNumDB,
{
    debug!("Starting deploy a contract...");

    let access_right = req.into_access_right()?;
    let deployer_addr = server.dispatcher.get_account(0)?;
    let contract_addr = server.dispatcher
        .deploy(&deployer_addr, &access_right)?;

    debug!("Contract address: {:?}", &contract_addr);

    Ok(HttpResponse::Ok().json(api::deploy::post::Response(contract_addr)))
}

pub fn handle_register<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<api::register::post::Request>,
) -> Result<HttpResponse, Error>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB=DB>,
    DB: BlockNumDB,
{
    unimplemented!();
}

pub fn handle_init_state<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<api::init_state::post::Request>,
) -> Result<HttpResponse, Error>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB=DB>,
    DB: BlockNumDB,
{
    let access_right = req.into_access_right()?;

    unimplemented!();
}

pub fn handle_state_transition<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<api::state_transition::post::Request>,
) -> Result<HttpResponse, Error>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB=DB>,
    DB: BlockNumDB,
{
    let access_right = req.into_access_right()?;
    let from_eth_addr = server.dispatcher.get_account(0)?;

    let receipt = server.dispatcher.state_transition(
        access_right,
        &req.target,
        Value::new(req.amount),
        req.state_id,
        from_eth_addr,
        DEFAULT_SEND_GAS,
        &req.contract_addr,
        &server.abi_path,
    )?;

    Ok(HttpResponse::Ok().json(api::state_transition::post::Response(receipt)))
}

/// Fetch events from blockchain nodes manually, and then get state from enclave.
pub fn handle_get_state<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<api::state::get::Request>,
) -> Result<HttpResponse, Error>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB=DB>,
    DB: BlockNumDB,
{
    server.dispatcher.block_on_event(&req.contract_addr, &server.abi_path)?;

    let access_right = req.into_access_right()?;
    let state = get_state_by_access_right::<Value>(&access_right, server.eid)?;

    Ok(HttpResponse::Ok().json(api::state::get::Response(state)))
}
