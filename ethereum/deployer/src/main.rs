use eth_deployer::EthDeployer;
use frame_config::{ANONIFY_ABI_PATH, ANONIFY_BIN_PATH, CREATE2_ABI_PATH, CREATE2_BIN_PATH};
use std::env;

const GAS: u64 = 5_000_000;

#[tokio::main]
async fn main() {
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
    let account_index = env::var("ACCOUNT_INDEX")
        .unwrap_or_else(|_| "0".to_string())
        .parse::<usize>()
        .unwrap();
    let password = env::var("PASSWORD").ok();
    let confirmations = env::var("CONFIRMATIONS")
        .expect("CONFIRMATIONS is not set")
        .parse::<usize>()
        .expect("Failed to parse CONFIRMATIONS to usize");
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 1);

    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer
        .get_account(account_index, password.as_deref())
        .await
        .unwrap();

    let contract_address = match args[0].as_str() {
        "create2" => deployer.deploy(
            &*CREATE2_ABI_PATH,
            &*CREATE2_BIN_PATH,
            confirmations,
            GAS,
            signer,
        ),
        _ => deployer.deploy(
            &*ANONIFY_ABI_PATH,
            &*ANONIFY_BIN_PATH,
            confirmations,
            GAS,
            signer,
        ),
    }
    .await
    .unwrap();

    println!("contract_address");
}
