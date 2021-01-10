use super::event_watcher::{EthEvent, Web3Logs};
use crate::{
    cache::EventCache,
    error::{HostError, Result},
    utils::ContractInfo,
    workflow::*,
};
use anonify_config::{REQUEST_RETRIES, RETRY_DELAY_MILLS};
use anyhow::anyhow;
use ethabi::{Topic, TopicFilter};
use frame_retrier::{strategy, Retry};
use std::{fs, path::Path};
use web3::{
    contract::{Contract, Options},
    transports::Http,
    types::{Address, BlockNumber, Filter, FilterBuilder, Log, H256},
    Web3,
};

const UNLOCK_DURATION: u16 = 60;
const EVENT_LIMIT: usize = 100;

// libsecp256k1 library generates RecoveryId as 0/1.
// However Secp256k1 used in solidity use 27/28 as a value to make a public key unique to recover.
// RECOVERY_ID_OFFSET is used to adjust the difference between libsecp256k1 and Secp256k1.
const RECOVERY_ID_OFFSET: u8 = 27;

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

    pub async fn send_report_handshake(
        &self,
        output: host_output::JoinGroup,
        method: &str,
    ) -> Result<H256> {
        let ecall_output = output
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;
        let report = ecall_output.report().to_vec();
        let report_sig = ecall_output.report_sig().to_vec();
        let handshake = ecall_output.handshake().to_vec();
        let gas = output.gas;

        Retry::new(
            "send_report_handshake",
            REQUEST_RETRIES,
            strategy::FixedDelay::new(RETRY_DELAY_MILLS),
        )
        .spawn_async(async || {
            self.contract
                .call(
                    method,
                    (
                        report,
                        report_sig,
                        handshake,
                        ecall_output.mrenclave_ver(),
                        ecall_output.roster_idx(),
                    ),
                    output.signer,
                    Options::with(|opt| opt.gas = Some(gas.into())),
                )
                .await
                .map_err(Into::into)
        })
        .await
    }

    pub async fn register_report(&self, output: host_output::RegisterReport) -> Result<H256> {
        let ecall_output = output
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;
        let report = ecall_output.report().to_vec();
        let report_sig = ecall_output.report_sig().to_vec();
        let gas = output.gas;

        self.contract
            .call(
                "registerReport",
                (
                    report,
                    report_sig,
                    ecall_output.mrenclave_ver(),
                    ecall_output.roster_idx(),
                ),
                output.signer,
                Options::with(|opt| opt.gas = Some(gas.into())),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn send_command(&self, output: host_output::Command) -> Result<H256> {
        let ecall_output = output
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;
        let ciphertext = ecall_output.encode_ciphertext();
        let mut enclave_sig = ecall_output.encode_enclave_sig().to_vec();
        let recovery_id = ecall_output.encode_recovery_id() + RECOVERY_ID_OFFSET;
        enclave_sig.push(recovery_id);
        let gas = output.gas;

        self.contract
            .call(
                "storeCommand",
                (ciphertext, enclave_sig),
                output.signer,
                Options::with(|opt| opt.gas = Some(gas.into())),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn handshake(&self, output: host_output::Handshake) -> Result<H256> {
        let ecall_output = output
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;
        let handshake = ecall_output.encode_handshake();
        let mut enclave_sig = ecall_output.encode_enclave_sig().to_vec();
        let recovery_id = ecall_output.encode_recovery_id() + RECOVERY_ID_OFFSET;
        enclave_sig.push(recovery_id);
        let gas = output.gas;

        self.contract
            .call(
                "handshake",
                (handshake, enclave_sig, ecall_output.roster_idx()),
                output.signer,
                Options::with(|opt| opt.gas = Some(gas.into())),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn get_event(&self, cache: EventCache, key: Address) -> Result<Web3Logs> {
        let events = EthEvent::create_event();
        let ciphertext_sig = events.ciphertext_signature();
        let handshake_sig = events.handshake_signature();
        // Read latest block number from in-memory event cache.
        let latest_fetched_num = cache
            .inner()
            .read()
            .get_latest_block_num(key)
            .unwrap_or_default();

        let filter = FilterBuilder::default()
            .address(vec![self.address])
            .topic_filter(TopicFilter {
                topic0: Topic::OneOf(vec![ciphertext_sig, handshake_sig]),
                topic1: Topic::Any,
                topic2: Topic::Any,
                topic3: Topic::Any,
            })
            .from_block(BlockNumber::Number(latest_fetched_num.into()))
            .to_block(BlockNumber::Latest)
            .limit(EVENT_LIMIT)
            .build();

        let logs = self.web3_conn.get_logs(filter).await?;

        Ok(Web3Logs::new(logs, cache, events))
    }

    pub async fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        self.web3_conn.get_account(index, password).await
    }

    pub fn address(&self) -> Address {
        self.address
    }
}

/// Basic web3 connection components via HTTP.
#[derive(Debug)]
pub struct Web3Http {
    web3: Web3<Http>,
    eth_url: String,
}

impl Web3Http {
    pub fn new(eth_url: &str) -> Result<Self> {
        let transport = Http::new(eth_url)?;
        let web3 = Web3::new(transport);

        Ok(Web3Http {
            web3,
            eth_url: eth_url.to_string(),
        })
    }

    pub async fn get_account(&self, index: usize, password: &str) -> Result<Address> {
        let account = self.web3.eth().accounts().await?[index];
        if !self
            .web3
            .personal()
            .unlock_account(account, password, Some(UNLOCK_DURATION))
            .await?
        {
            return Err(HostError::UnlockError);
        }

        Ok(account)
    }

    pub async fn get_logs(&self, filter: Filter) -> Result<Vec<Log>> {
        self.web3.eth().logs(filter).await.map_err(Into::into)
    }

    pub async fn deploy<P: AsRef<Path>>(
        &self,
        output: host_output::JoinGroup,
        abi_path: P,
        bin_path: P,
        confirmations: usize,
    ) -> Result<Address> {
        let abi = fs::read(abi_path)?;
        let bin = fs::read_to_string(bin_path)?;

        let ecall_output = output
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;
        let report = ecall_output.report().to_vec();
        let report_sig = ecall_output.report_sig().to_vec();
        let handshake = ecall_output.handshake().to_vec();
        let gas = output.gas;

        let contract = Contract::deploy(self.web3.eth(), abi.as_slice())
            .map_err(|e| anyhow!("{:?}", e))?
            .options(Options::with(|opt| opt.gas = Some(gas.into())))
            .confirmations(confirmations)
            .execute(
                bin.as_str(),
                (report, report_sig, handshake, ecall_output.mrenclave_ver()),
                output.signer,
            )
            .map_err(|e| anyhow!("{:?}", e))?
            .await
            .map_err(|e| anyhow!("{:?}", e))?;

        Ok(contract.address())
    }

    pub fn get_eth_url(&self) -> &str {
        &self.eth_url
    }
}
