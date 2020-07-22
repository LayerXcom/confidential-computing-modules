use log::debug;
use std::{
    path::Path,
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
    Topic,
    TopicFilter,
    Event,
    EventParam,
    ParamType,
    decode,
    Hash,
};
use frame_common::crypto::Ciphertext;
use anyhow::anyhow;
use crate::{
    error::Result,
    eventdb::{BlockNumDB, InnerEnclaveLog, EnclaveLog},
    utils::ContractInfo,
    workflow::*,
};

pub const CONFIRMATIONS: usize = 0;
pub const DEPLOY_GAS: u64 = 5_000_000;

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
        handshake: &[u8],
    ) -> Result<Address> {
        let abi = include_bytes!("../../../../contract-build/Anonify.abi");
        let bin = include_str!("../../../../contract-build/Anonify.bin");

        let contract = Contract::deploy(self.web3.eth(), abi)
            .map_err(|e| anyhow!("{:?}", e))?
            .confirmations(CONFIRMATIONS)
            .options(Options::with(|opt| opt.gas = Some(DEPLOY_GAS.into())))
            .execute(
                bin,
                (report.to_vec(), report_sig.to_vec(), handshake.to_vec()), // Parameters are got from ecall, so these have to be allocated.
                *deployer,
            )
            .map_err(|e| anyhow!("{:?}", e))?
            .wait()
            .map_err(|e| anyhow!("{:?}", e))?;

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

    pub fn join_group<G: Into<U256>>(
        &self,
        from: Address,
        report: &[u8],
        report_sig: &[u8],
        handshake: &[u8],
        gas: G,
    ) -> Result<H256> {
        let call = self.contract.call(
            "join_group",
            (report.to_vec(), report_sig.to_vec(), handshake.to_vec()),
            from,
            Options::with(|opt| opt.gas = Some(gas.into())),
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }

    pub fn send_instruction(
        &self,
        output: host_output::Instruction,
    ) -> Result<H256> {
        let ciphertext = output.ciphertext.unwrap();
        let enclave_sig = output.enclave_sig.unwrap();
        let msg = output.msg.unwrap();
        let gas = output.gas;

        let call = self.contract.call(
            "storeInstruction",
            (ciphertext, enclave_sig.to_vec(), H256::from_slice(&msg)),
            output.signer,
            Options::with(|opt| opt.gas = Some(gas.into())),
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }

    pub fn handshake<G: Into<U256>>(
        &self,
        from: Address,
        handshake: &[u8],
        gas: G,
    ) -> Result<H256> {
        let call = self.contract.call(
            "handshake",
            handshake.to_vec(),
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
        key: Address,
    ) -> Result<Web3Logs<D>> {
        let events = EthEvent::create_event();
        // Read latest block number from in-memory event db.
        let latest_fetched_num = block_num_db.get_latest_block_num(key);
        let mut logs_acc = vec![];

        for event in &events.0 {
            let sig = event.signature();

            let filter = FilterBuilder::default()
                .address(vec![self.address])
                .topic_filter(TopicFilter {
                    topic0: Topic::This(sig),
                    topic1: Topic::Any,
                    topic2: Topic::Any,
                    topic3: Topic::Any,
                })
                .from_block(BlockNumber::Number(latest_fetched_num))
                .to_block(BlockNumber::Latest)
                .build();

            let logs = self.web3_conn.get_logs(filter)?;
            logs_acc.extend_from_slice(&logs);
        }

        Ok(Web3Logs {
            logs: logs_acc,
            db: block_num_db,
            events,
        })
    }

    pub fn get_account(&self, index: usize) -> Result<Address> {
        self.web3_conn.get_account(index)
    }

    pub fn address(&self) -> Address {
        self.address
    }
}

/// Event fetched logs from smart contracts.
#[derive(Debug)]
pub struct Web3Logs<D: BlockNumDB>{
    logs: Vec<Log>,
    db: Arc<D>,
    events: EthEvent,
}

impl<D: BlockNumDB> Web3Logs<D> {
    pub fn into_enclave_log(self) -> Result<EnclaveLog<D>> {
        let mut ciphertexts: Vec<Ciphertext> = vec![];
        let mut handshakes: Vec<Vec<u8>> = vec![];

        // If log data is not fetched currently, return empty EnclaveLog.
        // This is occurred when it fetched data of dupulicated block number.
        if self.logs.len() == 0 {
            return Ok(EnclaveLog{
                inner: None,
                db: self.db,
            });
        }

        let contract_addr = self.logs[0].address;
        let mut latest_blc_num = 0;
        let ciphertext_size = Self::decode_data(&self.logs[0]).len();

        for (i, log) in self.logs.iter().enumerate() {
            debug!("log: {:?}, \nindex: {:?}", log, i);
            if contract_addr != log.address {
                return Err(anyhow!("Each log should have same contract address.: index: {}", i).into());
            }

            let mut data = Self::decode_data(&log);

            // Processing conditions by ciphertext or handshake event
            if log.topics[0] == self.events.ciphertext_signature() {
                if ciphertext_size != data.len() && data.len() != 0  {
                    return Err(anyhow!("Each log should have same size of data.: index: {}", i).into());
                }
                let res = Ciphertext::from_bytes(&mut data[..], ciphertext_size);

                ciphertexts.push(res);
            } else if log.topics[0] == self.events.handshake_signature() {
                handshakes.push(data);
            } else {
                return Err(anyhow!("Invalid topics").into());
            }

            // Update latest block number
            if let Some(blc_num) = log.block_number {
                let blc_num = blc_num.as_u64();
                if latest_blc_num < blc_num {
                    latest_blc_num = blc_num
                }
            }
        }

        Ok(EnclaveLog {
            inner : Some(InnerEnclaveLog {
                contract_addr: contract_addr.to_fixed_bytes(),
                latest_blc_num: latest_blc_num,
                ciphertexts,
                handshakes,
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
#[derive(Debug)]
pub struct EthEvent(Vec<Event>);

impl EthEvent {
    pub fn create_event() -> Self {
        let events = vec![
            Event {
                name: "StoreCiphertext".to_owned(),
                inputs: vec![
                    EventParam {
                        name: "ciphertext".to_owned(),
                        kind: ParamType::Bytes,
                        indexed: false,
                    },
                ],
                anonymous: false,
            },
            Event {
                name: "StoreHandshake".to_owned(),
                inputs: vec![
                    EventParam {
                        name: "handshake".to_owned(),
                        kind: ParamType::Bytes,
                        indexed: false,
                    },
                ],
                anonymous: false,
            }
        ];

        EthEvent(events)
    }

    pub fn ciphertext_signature(&self) -> Hash {
        self.0[0].signature()
    }

    pub fn handshake_signature(&self) -> Hash {
        self.0[1].signature()
    }
}
