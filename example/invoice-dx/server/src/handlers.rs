use std::{sync::{Arc, mpsc}, env, thread, time};
use failure::Error;
use log::debug;
// use anonify_host::dispatcher::get_state;
use anonify_bc_connector::{
    // EventDB,
    BlockNumDB,
    traits::*,
    // eth::*,
};
use anonify_runtime::{Bytes, UpdatedState};
use anonify_host::Dispatcher;
use dx_app::send_invoice;
use actix_web::{
    web,
    HttpResponse,
};
// use anyhow::anyhow;
use sgx_types::sgx_enclave_id_t;
use crate::moneyforward::MFClient;
use crate::sunabar;

#[derive(Debug)]
pub struct Server<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    pub eid: sgx_enclave_id_t,
    pub eth_url: String,
    pub abi_path: String,
    pub dispatcher: Dispatcher<D, S, W, DB>,
}

impl<D, S, W, DB> Server<D, S, W, DB>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        let eth_url = env::var("ETH_URL").expect("ETH_URL is not set.");
        let abi_path = env::var("ANONYMOUS_ASSET_ABI_PATH").expect("ANONYMOUS_ASSET_ABI_PATH is not set.");
        let event_db = Arc::new(DB::new());
        let dispatcher = Dispatcher::<D, S, W, DB>::new(eid, &eth_url, event_db).unwrap();

        Server {
            eid,
            eth_url,
            abi_path,
            dispatcher,
        }
    }
}

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

pub fn handle_start_sync_bc<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<api::state::sync_bc::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer + Send + Sync + 'static,
        S: Sender + Send + Sync + 'static,
        W: Watcher<WatcherDB=DB> + Send + Sync + 'static,
        DB: BlockNumDB + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        loop {
            debug!("event fetched...");
            let shared_invoices = server
                .dispatcher
                .block_on_event::<_, Bytes>(&req.contract_addr, &server.abi_path).unwrap();

            if let Some(invoices) = shared_invoices {
                for invoice in invoices {
                    tx.send(invoice).unwrap()
                }
            }

            thread::sleep(time::Duration::from_secs(3));
        }
    });

    let shared_invoice = rx.recv();

    Ok(HttpResponse::Ok().finish())
}
