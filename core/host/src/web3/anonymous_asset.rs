use std::{
    sync::Arc,
    path::Path,
    time,
    io::BufReader,
    fs::File,
};
use crate::{
    error::*,
    constants::*,
};
use web3::{
    Web3,
    transports::{EventLoopHandle, Http},
    contract::{Contract, Options},
    types::{Address, Bytes, H160, H256, TransactionReceipt, U256, FilterBuilder, Filter, Log},
    futures::Future,
};
use log::debug;
use ethabi::Contract as ContractABI;
use anonify_common::Keccak256;

pub fn deploy(
    eth_url: &str,
    init_ciphertext: &[u8],
    report: &[u8],
    report_sig: &[u8],
) -> Result<Address> {
    let (eloop, transport) = Http::new(eth_url)?;
    let web3 = Web3::new(transport);
    let account = web3.eth().accounts().wait()?[0];

    let abi = include_bytes!("../../../../build/AnonymousAsset.abi");
    let bin = include_str!("../../../../build/AnonymousAsset.bin");

    let contract = Contract::deploy(web3.eth(), abi)
        .unwrap() // TODO
        .confirmations(CONFIRMATIONS)
        // .poll_interval(time::Duration::from_secs(POLL_INTERVAL_SECS))
        .options(Options::with(|opt| opt.gas = Some(DEPLOY_GAS.into())))
        .execute(
            bin,
            (init_ciphertext.to_vec(), report.to_vec(), report_sig.to_vec()), // Parameters are got from ecall, so these have to be allocated.
            account,
        )
        .unwrap() // TODO
        .wait()
        .unwrap(); // TODO

    Ok(contract.address())
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
        update_balance1: &[u8],
        update_balance2: &[u8],
        report: &[u8],
        report_sig: &[u8],
        gas: G,
    ) -> Result<H256> {
        let call = self.contract.call(
            "transfer",
            (update_balance1.to_vec(), update_balance2.to_vec(), report.to_vec(), report_sig.to_vec()),
            self.address,
            Options::with(|opt| opt.gas = Some(gas.into())),
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }

    pub fn get_event(&self, event_name: &str) -> Result<Vec<Log>> {
        let filter = FilterBuilder::default()
            .address(vec![self.address])
            .topics(Some(vec![(event_name.as_bytes().keccak256()).into()]), None, None, None)
            .build();

        let logs = self.web3.eth().logs(filter).wait()?;
        Ok(logs)
    }
}

pub fn contract_abi_from_path<P: AsRef<Path>>(path: P) -> Result<ContractABI> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let contract_abi = ContractABI::load(reader).expect("Failed to load contract abi.");
    Ok(contract_abi)
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
    use rand_core::RngCore;
    use rand_os::OsRng;
    use rand::Rng;
    use ed25519_dalek::Keypair;
    use crate::init_enclave::EnclaveDir;
    use crate::ecalls::init_state;

    const ETH_URL: &'static str = "http://172.18.0.2:8545";

    #[test]
    fn test_deploy_contract() {
        let enclave = EnclaveDir::new().init_enclave(true).unwrap();
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&msg);
        assert!(keypair.verify(&msg, &sig).is_ok());

        let total_supply = 100;

        let unsigned_tx = init_state(
            enclave.geteid(),
            &sig.to_bytes(),
            &keypair.public.to_bytes(),
            &msg,
            total_supply,
        ).unwrap();

        let contract_addr = deploy(
            ETH_URL,
            &unsigned_tx.ciphertexts,
            &unsigned_tx.report,
            &unsigned_tx.report_sig
        ).unwrap();

        println!("deployed contract address: {}", contract_addr);
    }

    #[test]
    fn test_transfer() {
        let enclave = EnclaveDir::new().init_enclave(true).unwrap();
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let sig = keypair.sign(&msg);
        assert!(keypair.verify(&msg, &sig).is_ok());

        let total_supply = 100;

        let unsigned_tx = init_state(
            enclave.geteid(),
            &sig.to_bytes(),
            &keypair.public.to_bytes(),
            &msg,
            total_supply,
        ).unwrap();

        let contract_addr = deploy(
            ETH_URL,
            &unsigned_tx.ciphertexts,
            &unsigned_tx.report,
            &unsigned_tx.report_sig
        ).unwrap();

        println!("deployed contract address: {}", contract_addr);

        let contract_abi = contract_abi_from_path(ANONYMOUS_ASSET_ABI_PATH).unwrap();
        let contract = AnonymousAssetContract::new(ETH_URL, contract_addr, contract_abi).unwrap();
        let logs = contract.get_event("Init").unwrap();
        println!("Init logs: {:?}", logs);

        
    }
}
