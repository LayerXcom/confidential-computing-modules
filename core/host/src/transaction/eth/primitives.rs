use log::debug;
use std::{
    path::Path,
    io::BufReader,
    fs::File,
    sync::Arc,
};
use web3::{
    Web3,
    transports::{EventLoopHandle, Http},
    contract::{Contract, Options},
    types::{Address, H256, U256, Filter, FilterBuilder, Log, BlockNumber},
    futures::Future,
};
use ethabi::{
    Contract as ContractABI,
    Topic,
    TopicFilter,
    Event,
    EventParam,
    ParamType,
    decode,
    Hash,
};
use anonify_common::{LockParam, IntoVec};
use anonify_app_preluder::Ciphertext;
use crate::{
    error::*,
    constants::*,
    transaction::{
        eventdb::{BlockNumDB, InnerEnclaveLog, EnclaveLog},
        utils::ContractInfo,
    },
};

/// Basic web3 connection components via HTTP.
#[derive(Debug)]
pub struct Web3Http {
    web3: Web3<Http>,
    eloop: EventLoopHandle,
    eth_url: String,
}

impl Web3Http {
    pub fn new(eth_url: &str) -> Result<Self> {
        let (eloop, transport) = Http::new(eth_url)?;
        let web3 = Web3::new(transport);

        Ok(Web3Http {
            web3,
            eloop,
            eth_url: eth_url.to_string(),
        })
    }

    pub fn get_account(&self, index: usize) -> Result<Address> {
        let account = self.web3.eth().accounts().wait()?[index];
        Ok(account)
    }

    pub fn get_logs(&self, filter: Filter) -> Result<Vec<Log>> {
        let logs = self.web3.eth().logs(filter).wait()?;
        Ok(logs)
    }

    pub fn deploy(
        &self,
        deployer: &Address,
        report: &[u8],
        report_sig: &[u8],
    ) -> Result<Address> {
        let abi = include_bytes!("../../../../../build/Anonify.abi");
        let bin = include_str!("../../../../../build/Anonify.bin");

        let contract = Contract::deploy(self.web3.eth(), abi)
            .unwrap() // TODO
            .confirmations(CONFIRMATIONS)
            // .poll_interval(time::Duration::from_secs(POLL_INTERVAL_SECS))
            .options(Options::with(|opt| opt.gas = Some(DEPLOY_GAS.into())))
            .execute(
                bin,
                (report.to_vec(), report_sig.to_vec()), // Parameters are got from ecall, so these have to be allocated.
                *deployer,
            )
            .unwrap() // TODO
            .wait()
            .unwrap(); // TODO

        Ok(contract.address())
    }

    pub fn get_eth_url(&self) -> &str {
        &self.eth_url
    }
}

/// Web3 connection components of a contract.
#[derive(Debug)]
pub struct Web3Contract {
    contract: Contract<Http>,
    address: Address, // contract address
    web3_conn: Web3Http,
}

impl Web3Contract {
    pub fn new<P: AsRef<Path>>(
        web3_conn: Web3Http,
        contract_info: ContractInfo<'_, P>
    ) -> Result<Self> {
        let abi = contract_info.contract_abi()?;
        let address = contract_info.address()?;
        let contract = Contract::new(web3_conn.web3.eth(), address, abi);

        Ok(Web3Contract {
            contract,
            address,
            web3_conn,
        })
    }

    pub fn register<G: Into<U256>>(
        &self,
        from: Address,
        report: &[u8],
        report_sig: &[u8],
        gas: G,
    ) -> Result<H256> {
        let call = self.contract.call(
            "register",
            (report.to_vec(), report_sig.to_vec()),
            from,
            Options::with(|opt| opt.gas = Some(gas.into())),
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }

    pub fn state_transition(
        &self,
        from: Address,
        state_id: u64,
        ciphertexts: impl Iterator<Item=Ciphertext>,
        lock_params: impl Iterator<Item=LockParam>,
        enclave_sig: &[u8],
        gas: u64,
    ) -> Result<H256> {
        let mut ct = vec![];
        ciphertexts
            .map(|e| e.into_vec())
            .for_each(|e| ct.push(e));

        let mut lp = vec![];
        lock_params
            .map(|e| H256::from_slice(e.as_bytes()))
            .for_each(|e| lp.push(e));

        let call = self.contract.call(
            "stateTransition",
            (U256::from(state_id), ct, lp, enclave_sig.to_vec()),
            from,
            Options::with(|opt| opt.gas = Some(gas.into())),
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }

    pub fn get_event<D: BlockNumDB>(
        &self,
        block_num_db: Arc<D>,
        key: Hash
    ) -> Result<Web3Logs<D>> {
        // Read latest block number from in-memory event db.
        let latest_fetched_num = block_num_db.get_latest_block_num(key);

        let filter = FilterBuilder::default()
            .address(vec![self.address])
            .topic_filter(TopicFilter {
                topic0: Topic::This(key),
                topic1: Topic::Any,
                topic2: Topic::Any,
                topic3: Topic::Any,
            })
            .from_block(BlockNumber::Number(latest_fetched_num))
            .to_block(BlockNumber::Latest)
            .build();

        let logs = self.web3_conn.get_logs(filter)?;
        Ok(Web3Logs {
            logs,
            db: block_num_db,
        })
    }

    pub fn get_account(&self, index: usize) -> Result<Address> {
        self.web3_conn.get_account(index)
    }
}

/// Event fetched logs from smart contracts.
#[derive(Debug)]
pub struct Web3Logs<D: BlockNumDB>{
    logs: Vec<Log>,
    db: Arc<D>,
}

impl<D: BlockNumDB> Web3Logs<D> {
    pub fn into_enclave_log(self) -> Result<EnclaveLog<D>> {
        let mut ciphertexts: Vec<Ciphertext> = vec![];

        // If log data is not fetched currently, return empty EnclaveLog.
        // This is occurred when it fetched data of dupulicated block number.
        if self.logs.len() == 0 {
            return Ok(EnclaveLog{
                inner: None,
                db: self.db
            });
        }

        let contract_addr = self.logs[0].address;
        let mut latest_blc_num = 0;
        let ciphertext_size = Self::decode_data(&self.logs[0]).len();

        for (i, log) in self.logs.iter().enumerate() {
            debug!("log: {:?}, \nindex: {:?}", log, i);

            if contract_addr != log.address {
                return Err(HostErrorKind::Web3Log{
                    msg: "Each log should have same contract address.",
                    index: i,
                }.into());
            }

            let data = Self::decode_data(&log);

            if ciphertext_size != data.len() && data.len() != 0  {
                return Err(HostErrorKind::Web3Log {
                    msg: "Each log should have same size of data.",
                    index: i,
                }.into());
            }

            if let Some(blc_num) = log.block_number {
                let blc_num = blc_num.as_u64();
                if latest_blc_num < blc_num {
                    latest_blc_num = blc_num
                }
            }

            ciphertexts.push(Ciphertext::from_bytes(&data[..]));
        }

        Ok(EnclaveLog {
            inner : Some(InnerEnclaveLog {
                contract_addr: contract_addr.to_fixed_bytes(),
                latest_blc_num: latest_blc_num,
                ciphertexts,
            }),
            db: self.db,
        })
    }

    fn decode_data(log: &Log) -> Vec<u8> {
        let tokens = decode(&[ParamType::Bytes], &log.data.0).expect("Failed to decode token.");
        let mut res = vec![];

        for token in tokens {
            res.extend_from_slice(&token.to_bytes()
                .expect("Failed to convert token into bytes."));
        }

        res
    }
}

/// A type of events from ethererum network.
pub struct EthEvent(Event);

impl EthEvent {
    pub fn build_event() -> Self {
        EthEvent(Event {
            name: "StoreCiphertext".to_owned(),
            inputs: vec![
                EventParam {
                    name: "ciphertext".to_owned(),
                    kind: ParamType::Bytes,
                    indexed: false,
                },
            ],
            anonymous: false,
        })
    }

    pub fn signature(&self) -> Hash {
        self.0.signature()
    }

    pub fn into_raw(&self) -> &Event {
        &self.0
    }
}

impl From<EthEvent> for Event {
    fn from(ev: EthEvent) -> Self {
        ev.0
    }
}
