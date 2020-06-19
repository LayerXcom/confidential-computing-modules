use std::{sync::{Arc, mpsc}, env, thread, time, path::PathBuf,};
use failure::Error;
use log::debug;
use actix_web::{
    web,
    HttpResponse,
};
use reqwest::Client;
use rand::rngs::OsRng;
use rand::Rng;
use ed25519_dalek::Keypair;
use sgx_types::sgx_enclave_id_t;

use anonify_bc_connector::{
    BlockNumDB,
    traits::*,
};
use anonify_runtime::{Bytes, UpdatedState};
use anonify_common::{UserAddress, AccessRight};
use anonify_host::Dispatcher;
use dx_app::send_invoice;

use crate::moneyforward::MFClient;
use crate::Server;
use crate::config::get_keypair_from_keystore;
use crate::sunabar::SunabarClient;

const DEFAULT_SEND_GAS: u64 = 3_000_000;
const DEFAULT_RECIPIENT_ADDRESS: &str = "KDY06J2T4bIldIq5Pjxo0Mq3ocY=";

pub fn handle_deploy<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<dx_api::deploy::post::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    debug!("Starting deploy a contract...");

    let deployer_addr = server.dispatcher.get_account(0)?;
    let contract_addr = server.dispatcher
        .deploy(&deployer_addr)?;

    debug!("Contract address: {:?}", &contract_addr);
    server.dispatcher.set_contract_addr(&contract_addr, &server.abi_path)?;

    Ok(HttpResponse::Ok().json(dx_api::deploy::post::Response(contract_addr)))
}

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

    let send_invoice_state = send_invoice { recipient, invoice };

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

pub fn handle_start_polling_moneyforward<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<dx_api::state::start_polling_moneyforward::Request>,
) -> Result<HttpResponse, Error>
    where
            D: Deployer,
            S: Sender,
            W: Watcher<WatcherDB=DB>,
            DB: BlockNumDB,
{
    let mf_client = MFClient::new();
    let (tx, rx) = mpsc::channel();

    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");
    // "as" and `0` is only used for DEMO.
    let keypair = get_keypair_from_keystore("as".as_bytes(), 0)
        .expect("failed to get keypair");
    let rng = &mut OsRng;

    let _ = thread::spawn(move || {
        loop {
            if mf_client.exists_new().unwrap() {
                debug!("new invoice exists");

                let invoice = mf_client.get_invoices()
                    .expect("failed to get invoice from moneyforward");
                tx.send(invoice).unwrap();
                break;
            }

            thread::sleep(time::Duration::from_secs(3));
        }
    });

    let invoice = &rx.recv().unwrap();
    let receipt = inner_send_invoice(server, keypair, invoice.to_string()).unwrap();

    println!("response from send_invoice: {}", receipt);

    Ok(HttpResponse::Ok().finish())
}

fn inner_send_invoice<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    keypair: Keypair,
    invoice: String,
) -> Result<String, Error>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    let access_right = create_access_right(keypair);
    let state_id: u64 = 0;
    let signer = server.dispatcher.get_account(0)?;
    let recipient: UserAddress = UserAddress::base64_decode(DEFAULT_RECIPIENT_ADDRESS);
    let contract_addr = env::var("CONTRACT_ADDR").unwrap_or_else(|_| String::default());

    let invoice = Bytes::new(invoice.clone().into());
    let invoice = Bytes::from(invoice);

    let send_invoice_state = send_invoice { recipient, invoice };

    let receipt = server.dispatcher.send_instruction(
        access_right,
        send_invoice_state,
        state_id,
        "send_invoice",
        signer,
        DEFAULT_SEND_GAS,
        &contract_addr,
        &server.abi_path,
    )?;

    Ok(receipt)
}

pub fn handle_start_sync_bc<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<dx_api::state::start_sync_bc::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer + Send + Sync + 'static,
        S: Sender + Send + Sync + 'static,
        W: Watcher<WatcherDB=DB> + Send + Sync + 'static,
        DB: BlockNumDB + Send + Sync + 'static,
{
    let client = SunabarClient::new();
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

    let res = client
        .set_shared_invoice(&rx.recv().unwrap())
        .transfer_request()
        .unwrap(); //todo

    println!("response from sunabar: {}", res);

    Ok(HttpResponse::Ok().finish())
}

pub fn handle_set_notification<D, S, W, DB>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<dx_api::notification::post::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer + Send + Sync + 'static,
        S: Sender + Send + Sync + 'static,
        W: Watcher<WatcherDB=DB> + Send + Sync + 'static,
        DB: BlockNumDB + Send + Sync + 'static,
{
    let keypair = get_keypair_from_keystore("as".as_bytes(), req.keyfile_index)
        .expect("failed to get keypair");
    let access_right = create_access_right(keypair);

    server.dispatcher.register_notification(access_right).unwrap();

    Ok(HttpResponse::Ok().finish())
}



fn create_access_right(keypair: Keypair) -> AccessRight {
    let rng = &mut OsRng;
    let challenge: [u8; 32] = rng.gen();
    let sig = keypair.sign(&challenge[..]);

    AccessRight::new(sig, keypair.public, challenge)
}
