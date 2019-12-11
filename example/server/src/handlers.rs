use actix_web::{
    web,
    HttpResponse,
};
use crate::{
    api,
    EnclaveId,
};
use anonify_host::prelude::anonify_deploy;

pub fn handle_post_deploy(
    enclave_id: web::Data<EnclaveId>,
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
