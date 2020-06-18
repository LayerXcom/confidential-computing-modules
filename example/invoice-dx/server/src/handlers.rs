use std::{sync::{Arc, mpsc}, env, thread, time, path::PathBuf,};
use failure::Error;
use log::debug;
use actix_web::{
    web,
    HttpResponse,
};
use reqwest::Client;
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use sgx_types::sgx_enclave_id_t;
// use anyhow::anyhow;

// use anonify_host::dispatcher::get_state;
use anonify_bc_connector::{
    // EventDB,
    BlockNumDB,
    traits::*,
    // eth::*,
};
use anonify_runtime::{Bytes, UpdatedState};
use anonify_common::UserAddress;
use anonify_host::Dispatcher;
use anonify_wallet::{
    WalletDirectory,
    KeystoreDirectory,
    // KeyFile,
    DirOperations,
};

use dx_app::send_invoice;
use dx_api;

use crate::moneyforward::MFClient;
use crate::Server;
use crate::config::get_default_root_dir;
use crate::sunabar::SunabarClient;

const DEFAULT_SEND_GAS: u64 = 3_000_000;
const DEFAULT_RECIPIENT_ADDRESS: &str = "KDY06J2T4bIldIq5Pjxo0Mq3ocY=";

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

pub fn handle_start_polling_moneyforward(
    req: web::Json<dx_api::state::start_polling_moneyforward::Request>,
) -> Result<HttpResponse, Error>
{
    let mf_client = MFClient::new();
    let (tx, rx) = mpsc::channel();

    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");
    let root_dir = get_default_root_dir();
    // "test" and `0` is only used for DEMO.
    let keypair = get_keypair_from_keystore(root_dir, "test".as_bytes(), 0)
        .expect("failed to get keypair");
    let state_id: u64 = 0;
    let recipient: UserAddress = UserAddress::base64_decode(DEFAULT_RECIPIENT_ADDRESS);
    let contract_addr = env::var("CONTRACT_ADDR").unwrap_or_else(|_| String::default());
    let rng = &mut OsRng;

    let _ = thread::spawn(move || {
        loop {
            if mf_client.exists_new().unwrap() {
                debug!("new invoice exists");
                let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");

                let invoice = mf_client.get_invoices()
                    .expect("failed to get invoice from moneyforward");
                tx.send(invoice).unwrap();
                break;
            }

            thread::sleep(time::Duration::from_secs(3));
        }
    });

    let invoice = &rx.recv().unwrap();
    let req = dx_api::send_invoice::post::Request::new(&keypair, state_id, recipient, invoice.to_string(), contract_addr, rng);
    let res = Client::new()
        .post(&format!("{}/api/v1/send_invoice", &anonify_url))
        .json(&req)
        .send().expect("failed to send invoice")
        .text().expect("failed to get the response text");

    println!("response from send_invoicer: {}", res);

    Ok(HttpResponse::Ok().finish())
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



fn wallet_keystore_dirs(root_dir: &PathBuf) -> Result<(WalletDirectory, KeystoreDirectory), Error> {
    // configure wallet directory
    let wallet_dir = WalletDirectory::create(&root_dir)?;

    // configure ketstore directory
    let keystore_dir_path = wallet_dir.get_default_keystore_dir();
    let keystore_dir = KeystoreDirectory::create(keystore_dir_path)?;

    Ok((wallet_dir, keystore_dir))
}

pub fn get_keypair_from_keystore(root_dir: PathBuf, password: &[u8], keyfile_index: usize) -> Result<Keypair, Error> {
    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;
    let keyfile = &keystore_dir.load_all()?[keyfile_index];
    let keypair = keyfile.get_key_pair(password)?;
    Ok(keypair)
}
