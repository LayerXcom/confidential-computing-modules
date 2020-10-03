use super::event_watcher::{EthEvent, Web3Logs};
use crate::{
    cache::EventCache,
    error::{HostError, Result},
    utils::ContractInfo,
    workflow::*,
};
use anyhow::anyhow;
use ethabi::{Topic, TopicFilter};
use parking_lot::RwLock;
use std::{fs, path::Path, sync::Arc};
use web3::{
    contract::{Contract, Options},
    futures::Future,
    transports::{EventLoopHandle, Http},
    types::{Address, BlockNumber, Filter, FilterBuilder, Log, TransactionReceipt},
    Web3,
};

const UNLOCK_DURATION: u16 = 60;
const EVENT_LIMIT: usize = 100;

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
        contract_info: ContractInfo<'_, P>,
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

    pub fn send_report_handshake(
        &self,
        output: host_output::JoinGroup,
        confirmations: usize,
        method: &str,
    ) -> Result<TransactionReceipt> {
        let ecall_output = output.ecall_output.unwrap();
        let report = ecall_output.report().to_vec();
        let report_sig = ecall_output.report_sig().to_vec();
        let handshake = ecall_output.handshake().to_vec();
        let gas = output.gas;

        let call = self.contract.call_with_confirmations(
            method,
            (report, report_sig, handshake, ecall_output.mrenclave_ver()),
            output.signer,
            Options::with(|opt| opt.gas = Some(gas.into())),
            confirmations,
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }

    pub fn send_instruction(
        &self,
        output: host_output::Instruction,
        confirmations: usize,
    ) -> Result<TransactionReceipt> {
        let ecall_output = output.ecall_output.unwrap();
        let ciphertext = ecall_output.encode_ciphertext();
        let enclave_sig = &ecall_output.encode_enclave_sig();
        let gas = output.gas;

        let call = self.contract.call_with_confirmations(
            "storeInstruction",
            (ciphertext, enclave_sig.to_vec()),
            output.signer,
            Options::with(|opt| opt.gas = Some(gas.into())),
            confirmations,
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }

    pub fn handshake(
        &self,
        output: host_output::Handshake,
        confirmations: usize,
    ) -> Result<TransactionReceipt> {
        let ecall_output = output.ecall_output.unwrap();
        let handshake = ecall_output.handshake().to_vec();
        let enclave_sig = &ecall_output.encode_enclave_sig();
        let gas = output.gas;

        let call = self.contract.call_with_confirmations(
            "handshake",
            (handshake, enclave_sig.to_vec()),
            output.signer,
            Options::with(|opt| opt.gas = Some(gas.into())),
            confirmations,
        );

        // https://github.com/tomusdrw/rust-web3/blob/c69bf938a0d3cfb5b64fca5974829408460e6685/src/confirm.rs#L253
        let res = call.wait().unwrap(); //TODO: error handling
        Ok(res)
    }

    pub fn get_event(&self, cache: Arc<RwLock<EventCache>>, key: Address) -> Result<Web3Logs> {
        let events = EthEvent::create_event();
        // Read latest block number from in-memory event cache.
        let latest_fetched_num = cache.read().get_latest_block_num(key).unwrap_or_default();
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
                .from_block(BlockNumber::Number(latest_fetched_num.into()))
                .to_block(BlockNumber::Latest)
                .limit(EVENT_LIMIT)
                .build();

            let logs = self.web3_conn.get_logs(filter)?;
            logs_acc.extend_from_slice(&logs);
        }

        Ok(Web3Logs::new(logs_acc, cache, events))
    }

    pub fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        self.web3_conn.get_account(index, password)
    }

    pub fn address(&self) -> Address {
        self.address
    }
}

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

    pub fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        let account = self.web3.eth().accounts().wait()?[index];
        if !self
            .web3
            .personal()
            .unlock_account(account, password, Some(UNLOCK_DURATION))
            .wait()?
        {
            return Err(HostError::UnlockError);
        }

        Ok(account)
    }

    pub fn get_logs(&self, filter: Filter) -> Result<Vec<Log>> {
        let logs = self.web3.eth().logs(filter).wait()?;
        Ok(logs)
    }

    pub fn deploy<P: AsRef<Path>>(
        &self,
        output: host_output::JoinGroup,
        confirmations: usize,
        abi_path: P,
        bin_path: P,
    ) -> Result<Address> {
        let abi = fs::read(abi_path)?;
        let bin = fs::read_to_string(bin_path)?;

        let ecall_output = output.ecall_output.unwrap();
        let report = ecall_output.report().to_vec();
        let report_sig = ecall_output.report_sig().to_vec();
        let handshake = ecall_output.handshake().to_vec();
        let gas = output.gas;

        let contract = Contract::deploy(self.web3.eth(), abi.as_slice())
            .map_err(|e| anyhow!("{:?}", e))?
            .confirmations(confirmations)
            .options(Options::with(|opt| opt.gas = Some(gas.into())))
            .execute(
                bin.as_str(),
                (report, report_sig, handshake, ecall_output.mrenclave_ver()),
                output.signer,
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
