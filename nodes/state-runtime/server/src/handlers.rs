use crate::error::{Result, ServerError};
use crate::{Server, DEFAULT_GAS};
use actix_web::{web, HttpResponse, Responder};
use anonify_eth_driver::traits::*;
use std::sync::Arc;

pub async fn handle_health_check() -> impl Responder {
    HttpResponse::Ok().finish()
}

pub async fn handle_update_mrenclave<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let tx_hash = server
        .dispatcher
        .update_mrenclave(server.sender_address, DEFAULT_GAS)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Accepted()
        .json(state_runtime_node_api::update_mrenclave::post::Response { tx_hash }))
}

pub async fn handle_send_command<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
    req: web::Json<state_runtime_node_api::state::post::Request>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let tx_hash = server
        .dispatcher
        .send_command(
            req.ciphertext.clone(),
            req.user_id,
            server.sender_address,
            DEFAULT_GAS,
        )
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Accepted().json(state_runtime_node_api::state::post::Response { tx_hash }))
}

pub async fn handle_key_rotation<S, W>(server: web::Data<Arc<Server<S, W>>>) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let tx_hash = server
        .dispatcher
        .handshake(server.sender_address, DEFAULT_GAS)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Accepted()
        .json(state_runtime_node_api::key_rotation::post::Response { tx_hash }))
}

/// Fetch events from blockchain nodes manually, and then get the state data from enclave.
pub async fn handle_get_state<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
    req: web::Json<state_runtime_node_api::state::get::Request>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .fetch_events()
        .await
        .map_err(|e| ServerError::from(e))?;

    let state = server
        .dispatcher
        .get_state(req.ciphertext.clone())
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(state_runtime_node_api::state::get::Response { state }))
}

/// Fetch events from blockchain nodes manually, and then get the user counter from enclave.
pub async fn handle_get_user_counter<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
    req: web::Json<state_runtime_node_api::user_counter::get::Request>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .fetch_events()
        .await
        .map_err(|e| ServerError::from(e))?;

    let user_counter = server
        .dispatcher
        .get_user_counter(req.ciphertext.clone())
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok()
        .json(state_runtime_node_api::user_counter::get::Response { user_counter }))
}

pub async fn handle_enclave_encryption_key<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let enclave_encryption_key = server
        .dispatcher
        .get_enclave_encryption_key()
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(
        state_runtime_node_api::enclave_encryption_key::get::Response {
            enclave_encryption_key,
        },
    ))
}

pub async fn handle_register_notification<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
    req: web::Json<state_runtime_node_api::register_notification::post::Request>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server
        .dispatcher
        .register_notification(req.ciphertext.clone())
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn handle_register_report<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    let tx_hash = server
        .dispatcher
        .register_report(server.sender_address, DEFAULT_GAS)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Accepted()
        .json(state_runtime_node_api::register_report::post::Response { tx_hash }))
}

#[cfg(feature = "backup-enable")]
pub async fn handle_all_backup_to<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server.dispatcher.all_backup_to()?;

    Ok(HttpResponse::Ok().finish())
}

#[cfg(feature = "backup-enable")]
pub async fn handle_all_backup_from<S, W>(
    server: web::Data<Arc<Server<S, W>>>,
) -> Result<HttpResponse>
where
    S: Sender,
    W: Watcher,
{
    server.dispatcher.all_backup_from()?;

    Ok(HttpResponse::Ok().finish())
}
