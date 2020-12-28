use crate::error::{Result, ServerError};
use crate::Server;
use actix_web::{web, HttpResponse};
use anonify_eth_driver::traits::*;
use anyhow::anyhow;
use erc20_state_transition::CallName;
use frame_runtime::primitives::{Approved, U64};
use log::{debug, error, info};
use std::{sync::Arc, time};

const DEFAULT_GAS: u64 = 5_000_000;

pub async fn handle_deploy<D, S, W>(server: web::Data<Arc<Server<D, S, W>>>) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    debug!("Starting deploy a contract...");

    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await
        .map_err(|e| ServerError::from(e))?;
    let contract_addr = server
        .dispatcher
        .deploy(
            sender_address,
            DEFAULT_GAS,
            &server.abi_path,
            &server.bin_path,
            server.confirmations,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

    debug!("Contract address: {:?}", &contract_addr);
    server
        .dispatcher
        .set_contract_addr(&contract_addr, &server.abi_path)
        .map_err(|e| ServerError::from(e))?;

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
        .await
        .map_err(|e| ServerError::from(e))?;
    let tx_hash = server
        .dispatcher
        .join_group(
            sender_address,
            DEFAULT_GAS,
            &req.contract_addr,
            &server.abi_path,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

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
        .await
        .map_err(|e| ServerError::from(e))?;
    let tx_hash = server
        .dispatcher
        .update_mrenclave(
            sender_address,
            DEFAULT_GAS,
            &req.contract_addr,
            &server.abi_path,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

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
        .await
        .map_err(|e| ServerError::from(e))?;
    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let encrypted_total_supply = req.encrypted_total_supply.clone();

    let tx_hash = server
        .dispatcher
        .send_command::<CallName, _>(
            access_right,
            encrypted_total_supply,
            "construct",
            sender_address,
            DEFAULT_GAS,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

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
        .await
        .map_err(|e| ServerError::from(e))?;
    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let encrypted_transfer_cmd = req.encrypted_transfer_cmd.clone();

    let tx_hash = server
        .dispatcher
        .send_command::<CallName, _>(
            access_right,
            encrypted_transfer_cmd,
            "transfer",
            sender_address,
            DEFAULT_GAS,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

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
        .await
        .map_err(|e| ServerError::from(e))?;
    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let encrypted_approve_cmd = req.encrypted_approve_cmd.clone();

    let tx_hash = server
        .dispatcher
        .send_command::<CallName, _>(
            access_right,
            encrypted_approve_cmd,
            "approve",
            sender_address,
            DEFAULT_GAS,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

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
        .await
        .map_err(|e| ServerError::from(e))?;
    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let encrypted_mint_cmd = req.encrypted_mint_cmd.clone();

    let tx_hash = server
        .dispatcher
        .send_command::<CallName, _>(
            access_right,
            encrypted_mint_cmd,
            "mint",
            sender_address,
            DEFAULT_GAS,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

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
        .await
        .map_err(|e| ServerError::from(e))?;
    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let encrypted_burn_cmd = req.encrypted_burn_cmd.clone();

    let tx_hash = server
        .dispatcher
        .send_command::<CallName, _>(
            access_right,
            encrypted_burn_cmd,
            "burn",
            sender_address,
            DEFAULT_GAS,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

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
        .await
        .map_err(|e| ServerError::from(e))?;
    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let encrypted_transfer_from_cmd = req.encrypted_transfer_from_cmd.clone();

    let tx_hash = server
        .dispatcher
        .send_command::<CallName, _>(
            access_right,
            encrypted_transfer_from_cmd,
            "transfer_from",
            sender_address,
            DEFAULT_GAS,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

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
        .await
        .map_err(|e| ServerError::from(e))?;
    let tx_hash = server
        .dispatcher
        .handshake(sender_address, DEFAULT_GAS)
        .await
        .map_err(|e| ServerError::from(e))?;

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
    server
        .dispatcher
        .fetch_events::<U64>()
        .await
        .map_err(|e| ServerError::from(e))?;

    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let owner_approved = server
        .dispatcher
        .get_state::<Approved, _, CallName>(access_right, "approved")
        .map_err(|e| ServerError::from(e))?;
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
    server
        .dispatcher
        .fetch_events::<U64>()
        .await
        .map_err(|e| ServerError::from(e))?;

    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let state = server
        .dispatcher
        .get_state::<U64, _, CallName>(access_right, "balance_of")
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::state::get::Response(state.as_raw())))
}

pub async fn handle_encrypting_key<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let pub_key = server
        .dispatcher
        .get_encrypting_key()
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::encrypting_key::get::Response(pub_key)))
}

pub async fn handle_start_sync_bc<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
) -> Result<HttpResponse>
where
    D: Deployer + Send + Sync + 'static,
    S: Sender + Send + Sync + 'static,
    W: Watcher + Send + Sync + 'static,
{
    // it spawns a new OS thread, and hosts an event loop.
    actix_rt::Arbiter::new().exec_fn(move || {
        actix_rt::spawn(async move {
            loop {
                match server.dispatcher.fetch_events::<U64>().await {
                    Ok(updated_states) => info!("State updated: {:?}", updated_states),
                    Err(err) => error!("event fetched error: {:?}", err),
                };
                actix_rt::time::delay_for(time::Duration::from_millis(server.sync_time)).await;
            }
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
        .set_contract_addr(&req.contract_addr, &server.abi_path)
        .map_err(|e| ServerError::from(e))?;

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
    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    server
        .dispatcher
        .register_notification(access_right)
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn handle_register_report<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::register_report::post::Request>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    let sender_address = server
        .dispatcher
        .get_account(server.account_index, &server.password)
        .await
        .map_err(|e| ServerError::from(e))?;
    let tx_hash = server
        .dispatcher
        .register_report(
            sender_address,
            DEFAULT_GAS,
            &req.contract_addr,
            &server.abi_path,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::register_report::post::Response(tx_hash)))
}
