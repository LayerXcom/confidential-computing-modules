use sgx_types::sgx_enclave_id_t;
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
    decode,
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

    pub fn get_event(&self, event: &Event) -> Result<Web3Logs> {
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
        Ok(Web3Logs(logs))
    }
}

#[derive(Debug)]
pub struct Web3Logs(pub Vec<Log>);

impl Web3Logs {
    pub fn into_enclave_log(&self, event: &Event) -> Result<EnclaveLog> {
        let mut ciphertexts: Vec<u8> = vec![];

        // TODO: How to handle mixied events.
        let ciphertexts_num = match event.name.as_str() {
            "Init" => self.0.len(),
            "Transfer" => self.0.len() * 2,
            _ => panic!("Invalid event name."),
        };

        let contract_addr = self.0[0].address;
        let block_number = self.0[0].block_number.expect("Should have block number.");

        for (i, log) in self.0.iter().enumerate() {
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

            let data = Self::decode_data(&log, &event);
            ciphertexts.extend_from_slice(&data[..]);
        }

        Ok(EnclaveLog {
            contract_addr: contract_addr.to_fixed_bytes(),
            block_number: block_number.as_u64(),
            ciphertexts,
            ciphertexts_num: ciphertexts_num as u32,
        })
    }

    fn decode_data(log: &Log, event: &Event) -> Vec<u8> {
        let param_types = event.inputs.iter().map(|e| e.kind.clone()).collect::<Vec<ParamType>>();
        let tokens = decode(&param_types, &log.data.0).expect("Failed to decode token.");
        let mut res = vec![];

        for token in tokens {
            res.extend_from_slice(&token.to_bytes()
                .expect("Failed to convert token into bytes."));
        }

        res
    }
}

/// A log which is sent to enclave. Each log containes ciphertexts data of a given contract address and a given block number.
pub struct EnclaveLog {
    pub contract_addr: [u8; 20],
    pub block_number: u64,
    pub ciphertexts: Vec<u8>, // Concatenated all ciphertexts within a specified block number.
    pub ciphertexts_num: u32, // The number of ciphertexts in logs within a specified block number.
}

impl EnclaveLog {
    pub fn insert_enclave(&self, eid: sgx_enclave_id_t) -> Result<()> {
        use crate::ecalls::insert_logs;

        insert_logs(eid, &self)?;
        Ok(())
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

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::RngCore;
    use rand_os::OsRng;
    use rand::Rng;
    use ed25519_dalek::Keypair;
    use anonify_common::UserAddress;
    use crate::init_enclave::EnclaveDir;
    use crate::ecalls::{init_state, get_state};
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
        let eid = enclave.geteid();
        let mut csprng: OsRng = OsRng::new().unwrap();
        let my_keypair: Keypair = Keypair::generate(&mut csprng);
        let my_msg = rand::thread_rng().gen::<[u8; 32]>();
        let my_sig = my_keypair.sign(&my_msg);

        let other_keypair: Keypair = Keypair::generate(&mut csprng);
        let other_msg = rand::thread_rng().gen::<[u8; 32]>();
        let other_sig = other_keypair.sign(&other_msg);

        assert!(my_keypair.verify(&my_msg, &my_sig).is_ok());
        assert!(other_keypair.verify(&other_msg, &other_sig).is_ok());

        let total_supply = 100;

        let unsigned_tx = init_state(
            eid,
            &my_sig,
            &my_keypair.public,
            &my_msg,
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

        let init_event = build_init_event();
        let logs = contract.get_event(&init_event).unwrap();
        println!("Init logs: {:?}", logs);
        logs.into_enclave_log(&init_event).unwrap().insert_enclave(eid).unwrap();

        let my_state = get_state(eid, &my_sig, &my_keypair.public, &my_msg).unwrap();
        assert_eq!(my_state, total_supply);

        let amount = 30;
        let gas = 3_000_000;

        let receipt = anonify_send(
            enclave.geteid(),
            &my_sig,
            &my_keypair.public,
            &my_msg,
            &UserAddress::from_pubkey(&other_keypair.public),
            amount,
            &contract,
            gas,
        );

        println!("receipt: {:?}", receipt);

        // let state = anonify_get_state(
        //     enclave.geteid(),
        //     &my_sig,
        //     &my_keypair.public,
        //     &my_msg,
        // ).unwrap();

        // println!("my state: {}", state);
    }
}
