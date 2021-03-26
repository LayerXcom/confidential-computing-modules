use eth_deployer::EthDeployer;
use frame_config::*;
use std::{env, str::FromStr};

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
    assert!(args.len() == 2 || args.len() == 3);

    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer
        .get_account(account_index, password.as_deref())
        .await
        .unwrap();

    match args[1].as_str() {
        "factory" => {
            let contract_address = deployer
                .deploy(
                    &*FACTORY_ABI_PATH,
                    &*FACTORY_BIN_PATH,
                    confirmations,
                    GAS,
                    signer,
                )
                .await
                .unwrap();
            println!("{:x}", contract_address);
        }
        "anonify_direct" => {
            let contract_address = deployer
                .deploy(
                    &*ANONIFY_ABI_PATH,
                    &*ANONIFY_BIN_PATH,
                    confirmations,
                    GAS,
                    signer,
                )
                .await
                .unwrap();
            println!("{:x}", contract_address);
        }
        "anonify_tk" => {
            let factory_address = web3::types::Address::from_str(args[2].as_str()).unwrap();

            let receipt = deployer
                .deploy_anonify_by_factory(
                    "deployAnonifyWithTreeKem",
                    &*FACTORY_ABI_PATH,
                    signer,
                    GAS,
                    factory_address,
                    confirmations,
                )
                .await
                .unwrap();
            println!("receipt: {:?}", receipt);
        }
        "anonify_ek" => {
            let factory_address = web3::types::Address::from_str(args[2].as_str()).unwrap();

            let receipt = deployer
                .deploy_anonify_by_factory(
                    "deployAnonifyWithEnclaveKey",
                    &*FACTORY_ABI_PATH,
                    signer,
                    GAS,
                    factory_address,
                    confirmations,
                )
                .await
                .unwrap();
            println!("receipt: {:?}", receipt);
        }
        _ => panic!("Invalid arguments"),
    };
}
