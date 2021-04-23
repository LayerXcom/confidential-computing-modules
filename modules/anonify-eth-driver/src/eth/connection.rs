use super::{event_def::*, event_watcher::Web3Logs};
use crate::{
    cache::EventCache,
    error::{HostError, Result},
    utils::{event_fetch_retry_condition, ContractInfo},
    workflow::*,
};
use anonify_ecall_types::CommandCiphertext;
use anyhow::anyhow;
use ethabi::{Topic, TopicFilter};
use frame_config::{REQUEST_RETRIES, RETRY_DELAY_MILLS};
use frame_retrier::{strategy, Retry};
use std::{env, fs, path::Path};
use web3::{
    contract::{Contract, Options},
    transports::Http,
    types::{Address, BlockNumber, Filter, FilterBuilder, Log, TransactionReceipt, H256},
    Web3,
    signing::{Key,SecretKeyRef},
};
use secp256k1::key::SecretKey;

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
    event_limit: usize,
    web3_signer: Web3Signer,
    confirmations: usize,
}

impl Web3Contract {
    pub fn new(web3_conn: Web3Http, contract_info: ContractInfo, confirmations: usize) -> Result<Self> {
        let abi = contract_info.contract_abi()?;
        let address = contract_info.address();
        let contract = Contract::new(web3_conn.web3.eth(), address, abi);
        let event_limit = env::var("EVENT_LIMIT")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<usize>()
            .expect("Failed to parse EVENT_LIMIT");
        let signer_pri_key = env::var("SIGNER_PRI_KEY").unwrap();
        let web3_signer = Web3Signer::new(&signer_pri_key).unwrap();

        Ok(Web3Contract {
            contract,
            address,
            web3_conn,
            event_limit,
            web3_signer,
            confirmations,
        })
    }

    pub async fn send_report_handshake(
        &self,
        output: host_output::JoinGroup,
        method: &str,
    ) -> Result<TransactionReceipt> {
        let ecall_output = output
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;
        let report = ecall_output.report().to_vec();
        let report_sig = ecall_output.report_sig().to_vec();
        let gas = output.gas;

        match ecall_output.handshake() {
            Some(handshake) => self
                .contract
                .signed_call_with_confirmations(
                    method,
                    (
                        report,
                        report_sig,
                        handshake.to_vec(),
                        ecall_output.mrenclave_ver(),
                        ecall_output.roster_idx(),
                    ),
                    Options::with(|opt| opt.gas = Some(gas.into())),
                    self.confirmations,
                    self.web3_signer.secret_key,
                )
                .await
                .map_err(Into::into),
            None => self
                .contract
                .call_with_confirmations(
                    method,
                    (
                        report,
                        report_sig,
                        ecall_output.mrenclave_ver(),
                        ecall_output.roster_idx(),
                    ),
                    output.signer,
                    Options::with(|opt| opt.gas = Some(gas.into())),
                    self.confirmations,
                )
                .await
                .map_err(Into::into),
        }
    }

    pub async fn register_report(&self, output: host_output::RegisterReport) -> Result<H256> {
        let ecall_output = output
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;
        let report = ecall_output.report().to_vec();
        let report_sig = ecall_output.report_sig().to_vec();
        let gas = output.gas;

        let receipt = self.contract
            .signed_call_with_confirmations(
                "registerReport",
                (
                    report,
                    report_sig,
                    ecall_output.mrenclave_ver(),
                    ecall_output.roster_idx(),
                ),
                Options::with(|opt| opt.gas = Some(gas.into())),
                self.confirmations,
                self.web3_signer.secret_key,
            )
            .await
            .map_err(Into::into);


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
        let mut enclave_sig = ecall_output.encode_enclave_sig().to_vec();
        let recovery_id = ecall_output.encode_recovery_id() + RECOVERY_ID_OFFSET;
        enclave_sig.push(recovery_id);
        let gas = output.gas;

        match ecall_output.ciphertext() {
            CommandCiphertext::TreeKem(ciphertext) => self
                .contract
                .call(
                    "storeCommand",
                    (
                        ciphertext.encode(),
                        enclave_sig,
                        ciphertext.roster_idx(),
                        ciphertext.generation(),
                        ciphertext.epoch(),
                    ),
                    output.signer,
                    Options::with(|opt| opt.gas = Some(gas.into())),
                )
                .await
                .map_err(Into::into),
            CommandCiphertext::EnclaveKey(ciphertext) => self
                .contract
                .call(
                    "storeCommand",
                    (ciphertext.encode(), enclave_sig, ciphertext.roster_idx()),
                    output.signer,
                    Options::with(|opt| opt.gas = Some(gas.into())),
                )
                .await
                .map_err(Into::into),
        }
    }

    pub async fn handshake(&self, output: host_output::Handshake) -> Result<H256> {
        let ecall_output = output
            .ecall_output
            .ok_or_else(|| HostError::EcallOutputNotSet)?;
        let handshake = ecall_output.handshake();
        let mut enclave_sig = ecall_output.encode_enclave_sig().to_vec();
        let recovery_id = ecall_output.encode_recovery_id() + RECOVERY_ID_OFFSET;
        enclave_sig.push(recovery_id);
        let gas = output.gas;

        self.contract
            .call(
                "handshake",
                (
                    handshake.encode(),
                    enclave_sig,
                    handshake.roster_idx(),
                    0 as u32,
                    handshake.prior_epoch() + 1,
                ),
                output.signer,
                Options::with(|opt| opt.gas = Some(gas.into())),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn get_event(&self, cache: EventCache, key: Address) -> Result<Web3Logs> {
        // Read latest block number from in-memory event cache.
        let latest_fetched_num = cache
            .inner()
            .read()
            .get_latest_block_num(key)
            .unwrap_or_default();

        let filter = FilterBuilder::default()
            .address(vec![self.address])
            .topic_filter(TopicFilter {
                topic0: Topic::OneOf(vec![
                    *STORE_TREEKEM_CIPHERTEXT_EVENT,
                    *STORE_TREEKEM_HANDSHAKE_EVENT,
                    *STORE_ENCLAVE_KEY_CIPHERTEXT_EVENT,
                ]),
                topic1: Topic::Any,
                topic2: Topic::Any,
                topic3: Topic::Any,
            })
            .from_block(BlockNumber::Number(latest_fetched_num.into()))
            .to_block(BlockNumber::Latest)
            // .limit(self.event_limit) // not work with Besu
            .build();

        let logs = Retry::new(
            "fetch_event",
            *REQUEST_RETRIES,
            strategy::FixedDelay::new(*RETRY_DELAY_MILLS),
        )
        .set_condition(event_fetch_retry_condition)
        .spawn_async(|| async { self.web3_conn.get_logs(&filter).await })
        .await?;

        Ok(Web3Logs::new(logs, cache))
    }

    pub async fn get_account(&self, index: usize, password: Option<&str>) -> Result<Address> {
        self.web3_conn.get_account(index, password).await
    }

    pub fn address(&self) -> Address {
        self.address
    }
}

/// Basic web3 connection components via HTTP.
#[derive(Debug)]
pub struct Web3Http {
    pub web3: Web3<Http>,
    eth_url: String,
    unlock_duration: u16,
}

impl Web3Http {
    pub fn new(eth_url: &str) -> Result<Self> {
        let transport = Http::new(eth_url)?;
        let web3 = Web3::new(transport);
        let unlock_duration = env::var("UNLOCK_DURATION")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<u16>()
            .expect("Failed to parse UNLOCK_DURATION");

        Ok(Web3Http {
            web3,
            eth_url: eth_url.to_string(),
            unlock_duration,
        })
    }

    pub async fn get_account(&self, index: usize, password: Option<&str>) -> Result<Address> {
        let accounts = self.web3.eth().accounts().await?;
        if accounts.len() <= index {
            return Err(anyhow!(
                "index {} is out of accounts length: {}",
                index,
                accounts.len()
            ))
            .map_err(Into::into);
        }
        let account = accounts[index];
        if let Some(pw) = password {
            if !self
                .web3
                .personal()
                .unlock_account(account, pw, Some(self.unlock_duration))
                .await?
            {
                return Err(HostError::UnlockError);
            }
        }

        Ok(account)
    }

    pub async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        self.web3
            .eth()
            .logs(filter.clone())
            .await
            .map_err(Into::into)
    }

    pub async fn deploy<P: AsRef<Path>>(
        &self,
        abi_path: P,
        bin_path: P,
        gas: u64,
        deployer: Address,
    ) -> Result<Address> {
        let abi = fs::read(abi_path)?;
        let bin = fs::read_to_string(bin_path)?;

        let contract = Contract::deploy(self.web3.eth(), abi.as_slice())?
            .options(Options::with(|opt| opt.gas = Some(gas.into())))
            .confirmations(self.confirmations)
            .execute(bin.as_str(), (), deployer)
            .await?;

        Ok(contract.address())
    }

    pub fn get_eth_url(&self) -> &str {
        &self.eth_url
    }
}

#[derive(Debug)]
struct Web3Signer {
    secret_key: SecretKey,
    address: Address,
}

impl Web3Signer {
    pub fn new(key: &str) -> Result<Self> {
        let secret_key: SecretKey = key.parse().unwrap();
        let secret_key_ref = SecretKeyRef::new(&secret_key);
        let address = secret_key_ref.address();

        Ok(Web3Signer {
            secret_key,
            address,
        })
    }
}