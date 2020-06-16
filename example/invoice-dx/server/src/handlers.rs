use std::sync::Arc;
// use std::{sync::Arc, thread, time};
use failure::Error;
// use log::debug;
// use anonify_host::dispatcher::get_state;
use anonify_bc_connector::{
    BlockNumDB,
    traits::*,
};
use anonify_runtime::{U64, Approved};
use erc20_app::send_invoice;
use actix_web::{
    web,
    HttpResponse,
};
// use anyhow::anyhow;

use crate::Server;

const DEFAULT_SEND_GAS: u64 = 3_000_000;

pub fn handle_send_invoice<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<dx_api::send_invoice::post::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    let access_right = req.into_access_right()?;
    let signer = server.dispatcher.get_account(0)?;
    let recipient = req.recipient;
    let body = Text::from(req.body)?;

    let send_invoice_state = send_invoice{ recipient, body };

    let receipt = server.dispatcher.send_instruction(
        access_right,
        send_invoice_state,
        req.state_id,
        "send_invoice",
        signer,
        DEFAULT_SEND_GAS,
        &req.contract_addr,
        &server.abi_path,
    )?;

    Ok(HttpResponse::Ok().json(dx_api::send_invoice::post::Response(receipt)))
}