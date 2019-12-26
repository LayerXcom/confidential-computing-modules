use failure::Error;
use log::debug;
use ed25519_dalek::{PublicKey, Signature};
use anonify_host::prelude::*;
use rocket_contrib::json::Json;
use crate::{ENCLAVE_ID, ETH_URL};

#[post("/deploy", format = "json", data = "<req>")]
pub fn handle_deploy(
    req: Json<api::deploy::post::Request>,
) -> String {
    debug!("Starting deploy a contract...");

    let sig = Signature::from_bytes(&req.sig).expect("Failed to get signature.");
    let pubkey = PublicKey::from_bytes(&req.pubkey).expect("Failed to get public key.");

    let access_right = AccessRight::new(sig, pubkey, req.nonce);

    let mut deployer = EthDeployer::new(*ENCLAVE_ID, ETH_URL)
        .expect("Failed to generate new deployer.");
    let deployer_addr = deployer.get_account(0)
        .expect("Failed to get a eth account.");
    let contract_addr = deployer.deploy(&deployer_addr, &access_right, req.total_supply)
        .expect("Failed to deploy a contract.");

    debug!("Contract address: {:?}", &contract_addr);

    hex::encode(contract_addr.to_fixed_bytes())
}
