use std::{sync::Arc, env, thread, time};
use failure::Error;
use log::debug;
use actix_web::{
    web,
    HttpResponse,
};
// use anyhow::anyhow;

// use anonify_host::dispatcher::get_state;
use anonify_bc_connector::{
    // EventDB,
    BlockNumDB,
    traits::*,
    // eth::*,
};
use anonify_runtime::Bytes;
use dx_app::send_invoice;

use crate::moneyforward::MFClient;
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
    let invoice = Bytes::new(req.invoice.clone().into());
    let invoice = Bytes::from(invoice);

    let send_invoice_state = send_invoice{ recipient, invoice };

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

pub fn handle_start_polling_moneyforward(
    req: web::Json<dx_api::state::start_polling_moneyforward::Request>,
) -> Result<HttpResponse, Error>
{
    let client = MFClient::new();

    let _ = thread::spawn(move || {
        loop {
            if client.exists_new().unwrap() {
                debug!("new invoice exists");
                break;
            }

            // let invoces = Billing::from_response(resp);

            // let = state_id: u64 = ; TODO:
            // let recipient: UserAddress = ; TODO:
            // let contract_addr = env::var("CONTRACT_ADDR").unwrap_or_else(|_| String::default());
            // let rng = &mut OsRng;
            // let req = api::send_invoice::post::Request::new(&keypair, state_id, recipient, body, contract_addr, rng);
            // let res = Client::new()
            //     .post(&format!("{}/api/v1/send_invoice", &anonify_url))
            //     .json(&req)
            //     .send()?
            //     .text()?;

            thread::sleep(time::Duration::from_secs(3));
        }
    });

    Ok(HttpResponse::Ok().finish())
}