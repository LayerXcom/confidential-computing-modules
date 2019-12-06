use std::{
    sync::Arc,
    path::Path,
    time,
};
use crate::{
    error::*,
    constants::*,
};
use web3::{
    Web3,
    transports::{EventLoopHandle, Http},
    contract::{Contract, Options},
    types::{Address, Bytes, H160, H256, TransactionReceipt, U256, FilterBuilder},
    futures::Future,
};
use ethabi::Contract as ContractABI;

pub fn deploy(
    eth_url: &str,
    init_balance: String,
    report: String,
    report_sig: String,
) -> Result<()> {
    let (eloop, transport) = Http::new(eth_url)?;
    let web3 = Web3::new(transport);
    let account = web3.eth().accounts().wait()?[0];

    let abi = include_bytes!("../../../../build/AnonymousAsset.abi");
    let bin = include_str!("../../../../build/AnonymousAsset.bin");

    let contract = Contract::deploy(web3.eth(), abi)
        .unwrap() // TODO
        .confirmations(CONFIRMATIONS)
        .poll_interval(time::Duration::from_secs(POLL_INTERVAL_SECS))
        .options(Options::with(|opt| opt.gas = Some(DEPLOY_GAS.into())))
        .execute(bin, (init_balance, report, report_sig), account)
        .unwrap() // TODO
        .wait()
        .unwrap(); // TODO

    // TODO: Show full logs.
    println!("contract address: {}", contract.address());

    Ok(())
}

#[derive(Debug)]
pub struct AnonymousAssetContract {
    contract: Contract<Http>,
    address: Address, // contract address
    web3: Web3<Http>,
    eloop: EventLoopHandle,
}

impl AnonymousAssetContract {
    pub fn new(eth_url: &str, contract_addr: Address, abi: ContractABI) -> Result<Self> {
        let (eloop, http) = Http::new(eth_url)?;
        let web3 = Web3::new(http);
        let contract = Contract::new(web3.eth(), contract_addr, abi);

        Ok(AnonymousAssetContract {
            contract,
            address: contract_addr,
            web3,
            eloop,
        })
    }

    pub fn tranfer<G: Into<U256>>(
        &self,
        from: Address,
        update_balance1: String,
        update_balance2: String,
        report: String,
        report_sig: String,
        gas: G,
    ) -> Result<H256> {
        let call = self.contract.call(
            "transfer",
            (update_balance1, update_balance2, report, report_sig),
            self.address,
            Options::with(|opt| opt.gas = Some(gas.into())),
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }
}

// pub fn get_logs(eth_url: &str, contract_addrss: Address) -> Result<()> {
//     let (eloop, transport) = Http::new(eth_url)?;
//     let web3 = Web3::new(transport);

//     let filter = FilterBuilder::default()
//         .address(vec![contract_address])
//         .topics(
//             Some(vec![]),
//             None,
//             None,
//             None,
//         )
//         .build();

//     let event_future = web3
//         .eth_filter()
//         .then(|filter| {
//             filter.unwrap().stream(time::Duration::from_secs(10)).for_each(|log| {
//                 println!("got log: {}", log);
//                 Ok(())
//             })
//         })
//         .map_err(|_| ());

//     let call_future = contract.call
// }


#[cfg(test)]
mod test {
    use super::*;

    const ETH_URL: &'static str = "http://127.0.0.1:8545";
    const report: &'static str = "";
    const report_sig: &'sttic str = "";

    #[test]
    #[ignore]
    fn test_deploy_contract() {
        let contract = AnonymousAssetContract::deploy(ETH_URL).unwrap();
    }
}
