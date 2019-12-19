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
    types::{Address, Bytes, H160, H256, TransactionReceipt, U256, FilterBuilder, Filter, Log, BlockNumber},
    futures::Future,
};
use log::debug;
use ethabi::{
    Contract as ContractABI,
    Topic,
    TopicFilter,
    Event,
    EventParam,
    ParamType,
};

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

    pub fn get_event(&self, event: Event) -> Result<Vec<Log>> {
        let filter = FilterBuilder::default()
            .address(vec![self.address])
            .topic_filter(TopicFilter {
                topic0: Topic::This(event.signature()),
                topic1: Topic::Any,
                topic2: Topic::Any,
                topic3: Topic::Any,
            })
            .from_block(BlockNumber::Earliest)
            .to_block(BlockNumber::Latest)
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

pub fn build_init_event() -> Event {
    Event {
        name: "Init".to_owned(),
        inputs: vec![
            EventParam {
                name: "_initBalance".to_owned(),
                kind: ParamType::Bytes,
                indexed: false,
            },
        ],
        anonymous: false,
    }
}

pub fn build_transfer_event() -> Event {
    Event {
        name: "Transfer".to_owned(),
        inputs: vec![
            EventParam {
                name: "_updateBalance1".to_owned(),
                kind: ParamType::Bytes,
                indexed: false,
            },
            EventParam {
                name: "_updateBalance2".to_owned(),
                kind: ParamType::Bytes,
                indexed: false,
            },
        ],
        anonymous: false,
    }
}

/// A log which is sent to enclave. Each log containes ciphertexts data of a given contract address and a given block number.
pub struct EnclaveLog {
    contract_addr: [u8; 20],
    block_number: u64,
    ciphertexts: Vec<u8>, // Concatenated all ciphertexts within a specified block number.
    ciphertexts_num: u32, // The number of ciphertexts in logs within a specified block number.
}

impl EnclaveLog {
    pub fn from_logs(logs: Vec<Log>, event: Event) -> Result<Self> {
        let mut ciphertexts: Vec<u8> = vec![];
        let ciphertexts_num = match event.name.as_str() {
            "Init" => logs.len(),
            "Transfer" => logs.len() * 2,
            _ => panic!("Invalid event."),
        };

        let contract_addr = logs[0].address;
        let block_number = logs[0].block_number.expect("Should have block number.");

        for (i, log) in logs.iter().enumerate() {
            if contract_addr != log.address {
                return Err(HostErrorKind::Web3Log{
                    msg: "Each log should have same contract address.",
                    index: i,
                }.into());
            }
            if block_number != log.block_number.unwrap() {
                return Err(HostErrorKind::Web3Log {
                    msg: "Each log should have same block number.",
                    index: i,
                }.into())
            }

            ciphertexts.extend_from_slice(&log.data.0[..]);
        }

        Ok(EnclaveLog {
            contract_addr: contract_addr.to_fixed_bytes(),
            block_number: block_number.as_u64(),
            ciphertexts,
            ciphertexts_num: ciphertexts_num as u32,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::RngCore;
    use rand_os::OsRng;
    use rand::Rng;
    use ed25519_dalek::Keypair;
    use anonify_common::UserAddress;
    use crate::init_enclave::EnclaveDir;
    use crate::ecalls::init_state;
    use crate::prelude::*;

    const ETH_URL: &'static str = "http://172.18.0.2:8545";
    pub const ANONYMOUS_ASSET_ABI_PATH: &str = "../../build/AnonymousAsset.abi";

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
            &sig,
            &keypair.public,
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
        let my_keypair: Keypair = Keypair::generate(&mut csprng);
        let other_keypair: Keypair = Keypair::generate(&mut csprng);

        let msg = rand::thread_rng().gen::<[u8; 32]>();
        let sig = my_keypair.sign(&msg);
        assert!(my_keypair.verify(&msg, &sig).is_ok());

        let total_supply = 100;

        let unsigned_tx = init_state(
            enclave.geteid(),
            &sig,
            &my_keypair.public,
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

        let event = build_init_event();
        let logs = contract.get_event(event).unwrap();
        println!("Init logs: {:?}", logs);

        let amount = 30;
        let gas = 3_000_000;

        let receipt = anonify_send(
            enclave.geteid(),
            &sig,
            &my_keypair.public,
            &msg,
            &UserAddress::from_pubkey(&other_keypair.public),
            amount,
            &contract,
            gas,
        );

        println!("receipt: {:?}", receipt);

        let state = anonify_get_state(
            enclave.geteid(),
            &sig,
            &my_keypair.public,
            &msg,
        ).unwrap();

        println!("my state: {}", state);
    }
}
