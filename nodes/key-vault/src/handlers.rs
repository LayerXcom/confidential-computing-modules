use crate::error::{Result, ServerError};
use crate::Server;
use actix_web::{web, HttpResponse, Responder};
use key_vault_ecall_types::cmd::*;
use std::sync::Arc;

pub async fn handle_health_check() -> impl Responder {
    HttpResponse::Ok().finish()
}

pub async fn handle_start(server: web::Data<Arc<Server>>) -> Result<HttpResponse> {
    server
        .dispatcher
        .start(START_SERVER_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn handle_stop(server: web::Data<Arc<Server>>) -> Result<HttpResponse> {
    server
        .dispatcher
        .stop(STOP_SERVER_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().finish())
}
