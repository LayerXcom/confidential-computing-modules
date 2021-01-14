use crate::error::{Result, ServerError};
use crate::Server;
use crate::api;
use key_vault_commands::*;
use actix_web::{web, HttpResponse};
use std::sync::Arc;

const SUCCESS: &'static str = r#"{
  "status": "success"
}"#;

pub async fn handle_start(server: web::Data<Arc<Server>>) -> Result<HttpResponse> {
    server
        .dispatcher
        .start(START_SERVER_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(
        HttpResponse::Ok().json(api::start::post::Response {
            status: "success".to_string(),
        }),
    )
}

pub async fn handle_stop(server: web::Data<Arc<Server>>) -> Result<HttpResponse> {
    server
        .dispatcher
        .stop(STOP_SERVER_CMD)
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(api::stop::post::Response(SUCCESS.to_string())))
}
