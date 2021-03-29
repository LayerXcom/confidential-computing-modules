use crate::Server;
use actix_web::{web, HttpResponse, Responder};
use std::sync::Arc;

pub async fn handle_health_check(server: web::Data<Arc<Server>>) -> impl Responder {
    if server.dispatcher.is_healthy() {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::ServiceUnavailable().finish()
    }
}
