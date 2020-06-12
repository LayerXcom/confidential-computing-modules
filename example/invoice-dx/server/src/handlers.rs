use std::{sync::Arc, thread, time};
use failure::Error;
use log::debug;
use anonify_host::dispatcher::get_state;
use anonify_bc_connector::{
    BlockNumDB,
    traits::*,
};
use anonify_runtime::{U64, Approved};
use dx_app::{approve, transfer, construct, transfer_from, mint, burn};
use actix_web::{
    web,
    HttpResponse,
};
use anyhow::anyhow;
use crate::Server;

const DEFAULT_SEND_GAS: u64 = 3_000_000;


pub fn handle_notify<D, S< W, DB>>(
    server: web::Data<Arc<Server<D, S, W, DB>>>,
    req: web::Json<api::state::start_polling::Request>,
) -> Result<HttpResponse, Error>
    where
        D: Deployer + Send + Sync + 'static,
        S: Sender + Send + Sync + 'static,
        W: Watcher<WatcherDB=DB> + Send + Sync + 'static,
        DB: BlockNumDB + Send + Sync + 'static,
{
    let access_right = req.into_access_right()?;
    let _ = thread::spawn(move || {
        loop {
            debug!("getting state...");
            let invoice = get_state::<U64>(&access_right, server.eid, "Invoice")?;

            thread::sleep(time::Duration::from_secs(3));
        }
    });

    Ok(HttpResponse::Ok().finish())
}
