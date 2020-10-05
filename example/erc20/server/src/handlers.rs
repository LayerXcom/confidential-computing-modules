use crate::Server;
use crate::error::{Result, ServerError};
use actix_web::{web, HttpResponse};
use anonify_eth_driver::{dispatcher::get_state, traits::*};
use erc20_state_transition::{
    approve, burn, construct, mint, transfer, transfer_from, CallName, MemName,
};
use frame_runtime::primitives::{Approved, U64};
use log::debug;
use std::{env, sync::Arc, time};

const DEFAULT_GAS: u64 = 5_000_000;

pub async fn handle_deploy<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    debug!("Starting deploy a contract...");

    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let (contract_addr, export_path_secret) = server
        .dispatcher
        .deploy(
            sender_address,
            DEFAULT_GAS,
            &server.abi_path,
            &server.bin_path,
        )
        .await.map_err(|e| ServerError::from(e))?;

    debug!("Contract address: {:?}", &contract_addr);
    debug!("export_path_secret: {:?}", export_path_secret);
    server
        .store_path_secrets
        .save_to_local_filesystem(&export_path_secret).map_err(|e| ServerError::from(e))?;
    server
        .dispatcher
        .set_contract_addr(&contract_addr, &server.abi_path).map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::deploy::post::Response(contract_addr)))
}

pub async fn handle_join_group<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::join_group::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let (tx_hash, export_path_secret) = server
        .dispatcher
        .join_group(
            sender_address,
            DEFAULT_GAS,
            &req.contract_addr,
            &server.abi_path,
        )
        .await.map_err(|e| ServerError::from(e))?;
    server
        .store_path_secrets
        .save_to_local_filesystem(&export_path_secret).map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::join_group::post::Response(tx_hash)))
}

pub async fn handle_update_mrenclave<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::update_mrenclave::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let (tx_hash, export_path_secret) = server
        .dispatcher
        .update_mrenclave(
            sender_address,
            DEFAULT_GAS,
            &req.contract_addr,
            &server.abi_path,
        )
        .await.map_err(|e| ServerError::from(e))?;
    server
        .store_path_secrets
        .save_to_local_filesystem(&export_path_secret).map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::update_mrenclave::post::Response(tx_hash)))
}

pub async fn handle_init_state<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::init_state::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let access_right = req.into_access_right().map_err(|e| ServerError::from(e))?;
    let total_supply = U64::from_raw(req.total_supply);
    let init_state = construct { total_supply };

    let tx_hash = server
        .dispatcher
        .send_instruction::<_, CallName, _>(
            access_right,
            init_state,
            "construct",
            sender_address,
            DEFAULT_GAS,
        )
        .await.map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::init_state::post::Response(tx_hash)))
}

pub async fn handle_transfer<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::transfer::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let access_right = req.into_access_right().map_err(|e| ServerError::from(e))?;
    let amount = U64::from_raw(req.amount);
    let recipient = req.target;
    let transfer_state = transfer { amount, recipient };

    let tx_hash = server
        .dispatcher
        .send_instruction::<_, CallName, _>(
            access_right,
            transfer_state,
            "transfer",
            sender_address,
            DEFAULT_GAS,
        )
        .await.map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::transfer::post::Response(tx_hash)))
}

pub async fn handle_approve<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::approve::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let access_right = req.into_access_right().map_err(|e| ServerError::from(e))?;
    let amount = U64::from_raw(req.amount);
    let spender = req.target;
    let approve_state = approve { amount, spender };

    let tx_hash = server
        .dispatcher
        .send_instruction::<_, CallName, _>(
            access_right,
            approve_state,
            "approve",
            sender_address,
            DEFAULT_GAS,
        )
        .await.map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::approve::post::Response(tx_hash)))
}

pub async fn handle_mint<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::mint::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let access_right = req.into_access_right().map_err(|e| ServerError::from(e))?;
    let amount = U64::from_raw(req.amount);
    let recipient = req.target;
    let minting_state = mint { amount, recipient };

    let tx_hash = server
        .dispatcher
        .send_instruction::<_, CallName, _>(
            access_right,
            minting_state,
            "mint",
            sender_address,
            DEFAULT_GAS,
        )
        .await.map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::mint::post::Response(tx_hash)))
}

pub async fn handle_burn<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::burn::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let access_right = req.into_access_right().map_err(|e| ServerError::from(e))?;
    let amount = U64::from_raw(req.amount);
    let burn_state = burn { amount };

    let tx_hash = server
        .dispatcher
        .send_instruction::<_, CallName, _>(
            access_right,
            burn_state,
            "burn",
            sender_address,
            DEFAULT_GAS,
        )
        .await.map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::burn::post::Response(tx_hash)))
}

pub async fn handle_transfer_from<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::transfer_from::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let access_right = req.into_access_right().map_err(|e| ServerError::from(e))?;
    let amount = U64::from_raw(req.amount);
    let owner = req.owner;
    let recipient = req.target;
    let transferred_from_state = transfer_from {
        owner,
        recipient,
        amount,
    };

    let tx_hash = server
        .dispatcher
        .send_instruction::<_, CallName, _>(
            access_right,
            transferred_from_state,
            "transfer_from",
            sender_address,
            DEFAULT_GAS,
        )
        .await.map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::transfer_from::post::Response(tx_hash)))
}

pub async fn handle_key_rotation<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await.map_err(|e| ServerError::from(e))?;
    let (tx_hash, export_path_secret) = server
        .dispatcher
        .handshake(sender_address, DEFAULT_GAS)
        .await.map_err(|e| ServerError::from(e))?;
    server
        .store_path_secrets
        .save_to_local_filesystem(&export_path_secret).map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::key_rotation::post::Response(tx_hash)))
}

/// Fetch events from blockchain nodes manually, and then get the balance of the address approved by the owner from enclave.
pub async fn handle_allowance<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::allowance::get::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    server.dispatcher.block_on_event::<U64>().await.map_err(|e| ServerError::from(e))?;

    let access_right = req.into_access_right().map_err(|e| ServerError::from(e))?;
    let owner_approved = get_state::<Approved, MemName, _>(access_right, server.eid, "Approved").map_err(|e| ServerError::from(e))?;
    let approved_amount = owner_approved.allowance(&req.spender).unwrap();
    // TODO: stop using unwrap when switching from failure to anyhow.

    Ok(HttpResponse::Ok().json(erc20_api::allowance::get::Response(
        (*approved_amount).as_raw(),
    )))
}

/// Fetch events from blockchain nodes manually, and then get balance of the address from enclave.
pub async fn handle_balance_of<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::state::get::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    server.dispatcher.block_on_event::<U64>().await.map_err(|e| ServerError::from(e))?;

    let access_right = req.into_access_right().map_err(|e| ServerError::from(e))?;
    let state = get_state::<U64, MemName, _>(access_right, server.eid, "Balance").map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::state::get::Response(state.as_raw())))
}

pub async fn handle_start_sync_bc<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
) -> Result<HttpResponse>
where
    D: Deployer + Send + Sync + 'static,
    S: Sender + Send + Sync + 'static,
    W: Watcher + Send + Sync + 'static,
{
    let sync_time: u64 = env::var("SYNC_BC_TIME")
        .unwrap_or_else(|_| "3".to_string())
        .parse()
        .expect("Failed to parse SYNC_BC_TIME to u64");

    // it spawns a new OS thread, and hosts an event loop.
    actix_rt::Arbiter::new().exec_fn(move || {
        actix_rt::spawn(async move {
            server.dispatcher.block_on_event::<U64>().await.unwrap();
            debug!("event fetched...");
            actix_rt::time::delay_for(time::Duration::from_secs(sync_time));
        });
    });

    Ok(HttpResponse::Ok().finish())
}

pub async fn handle_set_contract_addr<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::contract_addr::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    debug!("Starting set a contract address...");

    debug!("Contract address: {:?}", &req.contract_addr);
    server
        .dispatcher
        .set_contract_addr(&req.contract_addr, &server.abi_path).map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn handle_register_notification<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::register_notification::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let access_right = req.into_access_right().map_err(|e| ServerError::from(e))?;
    server.dispatcher.register_notification(access_right).map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().finish())
}
