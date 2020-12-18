use crate::error::{Result, ServerError};
use crate::Server;
use actix_web::{web, HttpResponse};
use anyhow::anyhow;
use std::sync::Arc;

pub async fn handle_start(server: web::Data<Arc<Server>>) -> Result<HttpResponse> {
    let resp = server
        .dispatcher
        .start(&server.server_private_key, &server.server_certificates)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(key_vault_example_api::start::post::Response(resp)))
}

pub async fn handle_stop(server: web::Data<Arc<Server>>) -> Result<HttpResponse> {
    let resp = server
        .dispatcher
        .stop()
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(key_vault_example_api::stop::post::Response(resp)))
}
