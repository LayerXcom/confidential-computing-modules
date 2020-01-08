use sgx_types::sgx_enclave_id_t;
use std::{
    path::Path,
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

/// Basic web3 connection components via HTTP.
#[derive(Debug)]
pub struct Web3Http {
    web3: Web3<Http>,
    eloop: EventLoopHandle,
}

impl Web3Http {
    pub fn new(eth_url: &str) -> Result<Self> {
        let (eloop, transport) = Http::new(eth_url)?;
        let web3 = Web3::new(transport);

        Ok(Web3Http {
            web3,
            eloop,
        })
    }

    pub fn get_account(&self, index: usize) -> Result<Address> {
        let account = self.web3.eth().accounts().wait()?[index];
        Ok(account)
    }

    pub fn get_logs(&self, filter: Filter) -> Result<Web3Logs> {
        let logs = self.web3.eth().logs(filter).wait()?;
        Ok(Web3Logs(logs))
    }

    pub fn deploy(
        &self,
        deployer: &Address,
        init_ciphertext: &[u8],
        report: &[u8],
        report_sig: &[u8],
    ) -> Result<Address> {
        let abi = include_bytes!("../../../../build/AnonymousAsset.abi");
        let bin = include_str!("../../../../build/AnonymousAsset.bin");

        let contract = Contract::deploy(self.web3.eth(), abi)
            .unwrap() // TODO
            .confirmations(CONFIRMATIONS)
            // .poll_interval(time::Duration::from_secs(POLL_INTERVAL_SECS))
            .options(Options::with(|opt| opt.gas = Some(DEPLOY_GAS.into())))
            .execute(
                bin,
                (init_ciphertext.to_vec(), report.to_vec(), report_sig.to_vec()), // Parameters are got from ecall, so these have to be allocated.
                *deployer,
            )
            .unwrap() // TODO
            .wait()
            .unwrap(); // TODO

        Ok(contract.address())
    }
}

/// Web3 connection components of anonymous asset contract.
#[derive(Debug)]
pub struct AnonymousAssetContract {
    contract: Contract<Http>,
    address: Address, // contract address
    web3_conn: Web3Http,
}

impl AnonymousAssetContract {
    pub fn new(web3_conn: Web3Http, address: Address, abi: ContractABI) -> Result<Self> {
        let contract = Contract::new(web3_conn.web3.eth(), address, abi);

        Ok(AnonymousAssetContract {
            contract,
            address,
            web3_conn,
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
            from,
            Options::with(|opt| opt.gas = Some(gas.into())),
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }

    pub fn get_event(&self, event: &EthEvent, from_block: BlockNumber) -> Result<Web3Logs> {

        let filter = FilterBuilder::default()
            .address(vec![self.address])
            .topic_filter(TopicFilter {
                topic0: Topic::This(event.into_raw().signature()),
                topic1: Topic::Any,
                topic2: Topic::Any,
                topic3: Topic::Any,
            })
            .from_block(from_block)
            .to_block(BlockNumber::Latest)
            .build();

        self.web3_conn.get_logs(filter)
    }

    pub fn get_account(&self, index: usize) -> Result<Address> {
        self.web3_conn.get_account(index)
    }
}

/// Event fetched logs from smart contracts.
#[derive(Debug)]
pub struct Web3Logs(pub Vec<Log>);

impl Web3Logs {
    pub fn into_enclave_log(&self, event: &EthEvent) -> Result<EnclaveLog> {
        let mut ciphertexts: Vec<u8> = vec![];

        // TODO: How to handle mixied events.
        let ciphertexts_num = match event.into_raw().name.as_str() {
            "Init" => self.0.len(),
            "Transfer" => self.0.len() * 2,
            _ => panic!("Invalid event name."),
        };

        // If log data is not fetched currently, return empty EnclaveLog.
        if self.0.len() == 0 {
            return Ok(EnclaveLog{ inner: None })
        }

        let contract_addr = self.0[0].address;
        let mut latest_blc_num = 0;
        // let block_number = self.0[0].block_number.expect("Should have block number.");

        for (i, log) in self.0.iter().enumerate() {
            if contract_addr != log.address {
                return Err(HostErrorKind::Web3Log{
                    msg: "Each log should have same contract address.",
                    index: i,
                }.into());
            }

            if let Some(blc_num) = log.block_number {
                let blc_num = blc_num.as_u64();
                if latest_blc_num < blc_num {
                    latest_blc_num = blc_num
                }
            }

            let data = Self::decode_data(&log, &event);
            ciphertexts.extend_from_slice(&data[..]);
        }

        Ok(EnclaveLog {
            inner : Some(InnerEnclaveLog {
                contract_addr: contract_addr.to_fixed_bytes(),
                latest_blc_num,
                ciphertexts,
                ciphertexts_num: ciphertexts_num as u32,
            })
        })
    }

    fn decode_data(log: &Log, event: &EthEvent) -> Vec<u8> {
        let param_types = event.into_raw()
            .inputs.iter()
            .map(|e| e.kind.clone()).collect::<Vec<ParamType>>();
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
#[derive(Debug, Clone)]
pub(crate) struct InnerEnclaveLog {
    pub(crate) contract_addr: [u8; 20],
    pub(crate) latest_blc_num: u64,
    pub(crate) ciphertexts: Vec<u8>, // Concatenated all ciphertexts within a specified block number.
    pub(crate) ciphertexts_num: u32, // The number of ciphertexts in logs within a specified block number.
}

#[derive(Debug, Clone)]
pub struct EnclaveLog {
    inner: Option<InnerEnclaveLog>,
}

impl EnclaveLog {
    /// Store logs into enclave in-memory.
    /// This returns
    pub fn insert_enclave(&self, eid: sgx_enclave_id_t) -> Result<()> {
        use crate::ecalls::insert_logs;
        match &self.inner {
            Some(log) => insert_logs(eid, log)?,
            None => return Ok(()),
        }

        Ok(())
    }

    pub fn get_latest_block_num(&self) -> u64 {
        match &self.inner {
            Some(log) => log.latest_blc_num,
            None => 0,
        }
    }
}

pub struct EthUserAddress(pub Address);

impl EthUserAddress {
    pub fn new(address: Address) -> Self {
        EthUserAddress(address)
    }
}

pub fn contract_abi_from_path<P: AsRef<Path>>(path: P) -> Result<ContractABI> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let contract_abi = ContractABI::load(reader).expect("Failed to load contract abi.");
    Ok(contract_abi)
}

/// A type of events from ethererum network.
pub struct EthEvent(Event);

impl EthEvent {
    pub fn build_init_event() -> Self {
        EthEvent(Event {
            name: "Init".to_owned(),
            inputs: vec![
                EventParam {
                    name: "_initBalance".to_owned(),
                    kind: ParamType::Bytes,
                    indexed: false,
                },
            ],
            anonymous: false,
        })
    }

    pub fn build_send_event() -> Self {
        EthEvent(Event {
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
