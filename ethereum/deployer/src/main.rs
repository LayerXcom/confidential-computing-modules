use eth_deployer::EthDeployer;
use std::env;

fn main() {
    let eth_url = env::var("ETH_URL").expect("ETH_URL is not set");
    let account_index = env::var("ACCOUNT_INDEX")
        .unwrap_or_else(|| "0".to_string())
        .parse::<usize>()
        .unwrap();
    let password = env::var("PASSWORD").ok();
    let deployer = EthDeployer::new(&eth_url).unwrap();
    let signer = deployer.get_account(account_index, password).await.unwrap();
}
