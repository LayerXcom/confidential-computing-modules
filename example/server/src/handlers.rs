use actix_web::{
    web,
    HttpResponse,
};
use crate::api;

pub fn handle_post_deploy(
    req: web::Json<api::deploy::post::Request>,
) -> HttpResponse {
    unimplemented!();
}

pub fn handle_post_transfer(

) {
    unimplemented!();
}

pub fn handle_get_balance() {
    unimplemented!();
}
