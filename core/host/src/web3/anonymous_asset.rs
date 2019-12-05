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
    types::{Address, Bytes, H160, H256, TransactionReceipt, U256},
    futures::Future,
};

#[derive(Debug)]
pub struct AnonymousAssetContract {
    web3: Arc<Web3<Http>>,
    eloop: EventLoopHandle,
    contract: Contract<Http>,
    account: Address, // deployer or function caller
}

impl AnonymousAssetContract {
    pub fn deploy(
        eth_url: &str,
        // deployer: Option<&str>,
    ) -> Result<Self> {
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
            .execute(bin, (), account)
            .unwrap() // TODO
            .wait()
            .unwrap(); // TODO

        Ok(AnonymousAssetContract {
            web3: Arc::new(web3),
            eloop,
            contract,
            account,
        })
    }

    pub fn from_deployed<P: AsRef<Path>>(
        contract_address: &str,
        abi_path: P,
        deployer: Option<&str>,
        eth_url: &str,
    ) -> Result<Self> {
        unimplemented!();
    }
}

pub trait Gets {
    fn get_balances(&self, offset: U256, len: U256) -> Result<Vec<String>>;
}

impl Gets for AnonymousAssetContract {
    fn get_balances(&self, offset: U256, len: U256) -> Result<Vec<String>> {
        let encrypted_balances = self.contract.query(
            "getBalances",
            (offset, len),
            self.account,
            Options::default(),
            None
        ).wait().unwrap(); // TODO

        Ok(encrypted_balances)
    }
}

pub trait Posts<G> {
    fn tranfer(&self, update_balance: String, report: String, signature: String, gas: G, confirmations: usize) -> Result<TransactionReceipt>;
}

impl<G: Into<U256>> Posts<G> for AnonymousAssetContract {
    fn tranfer(
        &self,
        update_balance: String,
        report: String,
        sig: String,
        gas: G,
        confirmations: usize
    ) -> Result<TransactionReceipt> {
        let call = self.contract.call_with_confirmations(
            "transfer",
            (update_balance, report.as_bytes().to_vec(), hex::decode(sig)?),
            self.account,
            Options::with(|opt| opt.gas = Some(gas.into())),
            confirmations
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        Ok(call.wait()?)
    }
}

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
