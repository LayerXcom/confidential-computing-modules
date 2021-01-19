use crate::error::{Result, ServerError};
use crate::Server;
use actix_web::{web, HttpResponse};
use anonify_eth_driver::traits::*;
use anyhow::anyhow;
use erc20_state_transition::{cmd::*, CallName};
use frame_runtime::primitives::{Approved, U64};
use std::{sync::Arc, time};
use tracing::{debug, error, info};

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
            JOIN_GROUP_CMD,
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
            JOIN_GROUP_CMD,
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
            JOIN_GROUP_CMD,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::update_mrenclave::post::Response(tx_hash)))
}

pub async fn handle_send_command<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
    req: web::Json<erc20_api::state::post::Request>,
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
        .send_command::<CallName, _>(
            req.encrypted_command.clone(),
            sender_address,
            DEFAULT_GAS,
            SEND_COMMAND_CMD,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::state::post::Response(tx_hash)))
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
        .handshake(sender_address, DEFAULT_GAS, SEND_HANDSHAKE_CMD)
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
        .fetch_events::<U64>(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let owner_approved = server
        .dispatcher
        .get_state::<Approved, _, CallName>(access_right, "approved", GET_STATE_CMD)
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
        .fetch_events::<U64>(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    let access_right = req
        .into_access_right()
        .map_err(|e| ServerError::from(anyhow!("{:?}", e)))?;
    let state = server
        .dispatcher
        .get_state::<U64, _, CallName>(access_right, "balance_of", GET_STATE_CMD)
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
        .get_encrypting_key(GET_ENCRYPTING_KEY_CMD)
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
                match server
                    .dispatcher
                    .fetch_events::<U64>(FETCH_CIPHERTEXT_CMD, FETCH_HANDSHAKE_CMD)
                    .await
                {
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
        .register_notification(access_right, REGISTER_NOTIFICATION_CMD)
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
            SEND_REGISTER_REPORT_CMD,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(erc20_api::register_report::post::Response(tx_hash)))
}

#[cfg(feature = "backup-enable")]
pub async fn handle_all_backup_to<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .all_backup_to(BACKUP_PATH_SECRET_ALL_CMD)?;

    Ok(HttpResponse::Ok().finish())
}

#[cfg(feature = "backup-enable")]
pub async fn handle_all_backup_from<D, S, W>(
    server: web::Data<Arc<Server<D, S, W>>>,
) -> Result<HttpResponse>
where
    D: Deployer,
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .all_backup_from(RECOVER_PATH_SECRET_ALL_CMD)?;

    Ok(HttpResponse::Ok().finish())
}
