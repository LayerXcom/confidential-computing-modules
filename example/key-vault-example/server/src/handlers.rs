use crate::error::{Result, ServerError};
use crate::Server;
use actix_web::{web, HttpResponse};
use std::sync::Arc;

const SUCCESS: &'static str = r#"{
  "status": "success"
}"#;

pub async fn handle_start(server: web::Data<Arc<Server>>) -> Result<HttpResponse> {
    server
        .dispatcher
        .start()
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(key_vault_example_api::start::post::Response(SUCCESS.to_string())))
}

pub async fn handle_stop(server: web::Data<Arc<Server>>) -> Result<HttpResponse> {
    server
        .dispatcher
        .stop()
        .await
        .map_err(|e| ServerError::from(e))?;

    Ok(HttpResponse::Ok().json(key_vault_example_api::stop::post::Response(SUCCESS.to_string())))
}
