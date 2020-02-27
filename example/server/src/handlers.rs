use std::sync::Arc;
use failure::Error;
use log::debug;
use anonify_host::dispatcher::get_state;
use anonify_rpc_handler::{
    BlockNumDB,
    traits::*,
};
use anonify_runtime::U64;
use app::{transfer, constructor};
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

    let deployer_addr = server.dispatcher.get_account(0)?;
    let contract_addr = server.dispatcher
        .deploy(&deployer_addr)?;

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
    let signer = server.dispatcher.get_account(0)?;
    let receipt = server.dispatcher.register(
        signer,
        DEFAULT_SEND_GAS,
        &req.contract_addr,
        &server.abi_path,
    )?;

    Ok(HttpResponse::Ok().json(api::register::post::Response(receipt)))
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
    let signer = server.dispatcher.get_account(0)?;
    let total_supply = U64::from_raw(req.total_supply);
    let init_state = constructor{ total_supply };

    let receipt = server.dispatcher.state_transition(
        access_right,
        init_state,
        req.state_id,
        "constructor",
        signer,
        DEFAULT_SEND_GAS,
        &req.contract_addr,
        &server.abi_path,
    )?;

    Ok(HttpResponse::Ok().json(api::init_state::post::Response(receipt)))
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
    let signer = server.dispatcher.get_account(0)?;
    let amount = U64::from_raw(req.amount);
    let recipient = req.target;
    let transfer_state = transfer{ amount, recipient };

    let receipt = server.dispatcher.state_transition(
        access_right,
        transfer_state,
        req.state_id,
        "transfer",
        signer,
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
    let state = get_state::<U64>(&access_right, server.eid, "Balance")?;

    Ok(HttpResponse::Ok().json(api::state::get::Response(state.as_raw())))
}
