use std::{sync::Arc, thread, time};
use failure::Error;
use log::debug;
use anonify_host::{
    dispatcher::get_state,
    BlockNumDB,
    traits::*,
};
use frame_runtime::primitives::{U64, Approved};
use erc20_state_transition::{
    MemName, CallName,
    approve, transfer, construct, transfer_from, mint, burn,
};
use actix_web::{
    web,
    HttpResponse,
};
use crate::Server;

const DEFAULT_GAS: u64 = 5_000_000;

pub fn handle_deploy<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
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
        .deploy(deployer_addr, DEFAULT_GAS)?;

    debug!("Contract address: {:?}", &contract_addr);
    server.dispatcher.set_contract_addr(&contract_addr, &server.abi_path)?;

    Ok(HttpResponse::Ok().json(erc20_api::deploy::post::Response(contract_addr)))
}

pub fn handle_join_group<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::join_group::post::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    let signer = server.dispatcher.get_account(0)?;
    let receipt = server.dispatcher.join_group(
        signer,
        DEFAULT_GAS,
        &req.contract_addr,
        &server.abi_path,
    )?;

    Ok(HttpResponse::Ok().json(erc20_api::join_group::post::Response(receipt)))
}

pub fn handle_init_state<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::init_state::post::Request>,
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
    let init_state = construct{ total_supply };

    let receipt = server.dispatcher.send_instruction::<_, CallName>(
        access_right,
        init_state,
        "construct",
        signer,
        DEFAULT_GAS,
    )?;

    Ok(HttpResponse::Ok().json(erc20_api::init_state::post::Response(receipt)))
}

pub fn handle_transfer<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::transfer::post::Request>,
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

    let receipt = server.dispatcher.send_instruction::<_, CallName>(
        access_right,
        transfer_state,
        "transfer",
        signer,
        DEFAULT_GAS,
    )?;

    Ok(HttpResponse::Ok().json(erc20_api::transfer::post::Response(receipt)))
}

pub fn handle_approve<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::approve::post::Request>,
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
    let spender = req.target;
    let approve_state = approve { amount, spender };

    let receipt = server.dispatcher.send_instruction::<_, CallName>(
        access_right,
        approve_state,
        "approve",
        signer,
        DEFAULT_GAS,
    )?;

    Ok(HttpResponse::Ok().json(erc20_api::approve::post::Response(receipt)))
}

pub fn handle_mint<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::mint::post::Request>,
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
    let minting_state = mint{ amount, recipient };

    let receipt = server.dispatcher.send_instruction::<_, CallName>(
        access_right,
        minting_state,
        "mint",
        signer,
        DEFAULT_GAS,
    )?;

    Ok(HttpResponse::Ok().json(erc20_api::mint::post::Response(receipt)))
}

pub fn handle_burn<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::burn::post::Request>,
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
    let burn_state = burn{ amount };

    let receipt = server.dispatcher.send_instruction::<_, CallName>(
        access_right,
        burn_state,
        "burn",
        signer,
        DEFAULT_GAS,
    )?;

    Ok(HttpResponse::Ok().json(erc20_api::burn::post::Response(receipt)))
}

pub fn handle_transfer_from<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::transfer_from::post::Request>,
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
    let owner = req.owner;
    let recipient = req.target;
    let transferred_from_state = transfer_from { owner, recipient, amount };

    let receipt = server.dispatcher.send_instruction::<_, CallName>(
        access_right,
        transferred_from_state,
        "transfer_from",
        signer,
        DEFAULT_GAS,
    )?;

    Ok(HttpResponse::Ok().json(erc20_api::transfer_from::post::Response(receipt)))
}

pub fn handle_key_rotation<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    let signer = server.dispatcher.get_account(0)?;
    let receipt = server.dispatcher.handshake(
        signer,
        DEFAULT_GAS,
    )?;

    Ok(HttpResponse::Ok().json(erc20_api::key_rotation::post::Response(receipt)))
}

/// Fetch events from blockchain nodes manually, and then get the balance of the address approved by the owner from enclave.
pub fn handle_allowance<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::allowance::get::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    server.dispatcher.block_on_event::<U64>()?;

    let access_right = req.into_access_right()?;
    let owner_approved = get_state::<Approved, MemName>(access_right, server.eid, "Approved")?;
    let approved_amount = owner_approved.allowance(&req.spender).unwrap();
    // TODO: stop using unwrap when switching from failure to anyhow.

    Ok(HttpResponse::Ok().json(erc20_api::allowance::get::Response((*approved_amount).as_raw())))
}

/// Fetch events from blockchain nodes manually, and then get balance of the address from enclave.
pub fn handle_balance_of<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::state::get::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    server.dispatcher.block_on_event::<U64>()?;

    let access_right = req.into_access_right()?;
    let state = get_state::<U64, MemName>(access_right, server.eid, "Balance")?;

    Ok(HttpResponse::Ok().json(erc20_api::state::get::Response(state.as_raw())))
}

pub fn handle_start_sync_bc<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer + Send + Sync + 'static,
        S: Sender + Send + Sync + 'static,
        W: Watcher<WatcherDB=DB> + Send + Sync + 'static,
        DB: BlockNumDB + Send + Sync + 'static,
{
    let _ = thread::spawn(move || {
        loop {
            server.dispatcher.block_on_event::<U64>().unwrap();
            debug!("event fetched...");
            thread::sleep(time::Duration::from_secs(3));
        }
    });

    Ok(HttpResponse::Ok().finish())
}

pub fn handle_set_contract_addr<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::contract_addr::post::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    debug!("Starting set a contract address...");

    debug!("Contract address: {:?}", &req.contract_addr);
    server.dispatcher.set_contract_addr(&req.contract_addr, &server.abi_path)?;

    Ok(HttpResponse::Ok().finish())
}

pub fn handle_register_notification<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<erc20_api::register_notification::post::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    let access_right = req.into_access_right()?;
    server.dispatcher.register_notification(access_right)?;

    Ok(HttpResponse::Ok().finish())
}
