use super::connection::{Web3Contract, Web3Http};
use crate::{cache::EventCache, error::Result, traits::*, utils::*, workflow::*};
use anyhow::anyhow;
use async_trait::async_trait;
use ethabi::{decode, Event, EventParam, Hash, ParamType};
use frame_common::{crypto::Ciphertext, state_types::UpdatedState, traits::*};
use frame_host::engine::HostEngine;
use log::debug;
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use std::{path::Path, sync::Arc};
use web3::types::{Address, Log};

/// Components needed to watch events
pub struct EventWatcher {
    contract: Web3Contract,
    cache: Arc<RwLock<EventCache>>,
}

#[async_trait]
impl Watcher for EventWatcher {
    fn new<P: AsRef<Path>>(
        node_url: &str,
        contract_info: ContractInfo<'_, P>,
        cache: Arc<RwLock<EventCache>>,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info)?;

        Ok(EventWatcher { contract, cache })
    }

    async fn block_on_event<S: State>(
        &self,
        eid: sgx_enclave_id_t,
    ) -> Result<Option<Vec<UpdatedState<S>>>> {
        let enclave_updated_state = self
            .contract
            .get_event(self.cache.clone(), self.contract.address())
            .await?
            .into_enclave_log()?
            // verification must be executed only before calling `insert_enclave`
            .insert_enclave(eid)?
            .save_cache(self.contract.address()); // cache must be saved only after calling `insert_enclave`.

        Ok(enclave_updated_state.updated_states())
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}

/// Event fetched logs from smart contracts.
#[derive(Debug)]
pub struct Web3Logs {
    logs: Vec<Log>,
    cache: Arc<RwLock<EventCache>>,
    events: EthEvent,
}

impl Web3Logs {
    pub fn new(logs: Vec<Log>, cache: Arc<RwLock<EventCache>>, events: EthEvent) -> Self {
        Web3Logs {
            logs,
            cache,
            events,
        }
    }

    pub fn into_enclave_log(self) -> Result<EnclaveLog> {
        let mut ciphertexts: Vec<Ciphertext> = vec![];
        let mut handshakes: Vec<Vec<u8>> = vec![];

        // If log data is not fetched currently, return empty EnclaveLog.
        // This is occurred when it fetched data of dupulicated block number.
        if self.logs.is_empty() {
            return Ok(EnclaveLog {
                inner: None,
                cache: self.cache,
            });
        }

        let contract_addr = self.logs[0].address;
        let mut latest_blc_num = 0;
        let ciphertext_size = Self::decode_data(&self.logs[0]).len();

        for (i, log) in self.logs.iter().enumerate() {
            debug!("Inserting enclave log: {:?}, \nindex: {:?}", log, i);
            if contract_addr != log.address {
                return Err(
                    anyhow!("Each log should have same contract address.: index: {}", i).into(),
                );
            }

            let mut data = Self::decode_data(&log);

            // Processing conditions by ciphertext or handshake event
            if log.topics[0] == self.events.ciphertext_signature() {
                if ciphertext_size != data.len() && !data.is_empty() {
                    return Err(
                        anyhow!("Each log should have same size of data.: index: {}", i).into(),
                    );
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

        // TODO: Decode handshake and then reordered and dedup as well.
        // Reordered by the priority in all fetched ciphertexts
        ciphertexts.sort();

        // Removes consecutive repeated message
        ciphertexts.dedup();

        Ok(EnclaveLog {
            inner: Some(InnerEnclaveLog {
                contract_addr: contract_addr.to_fixed_bytes(),
                latest_blc_num,
                ciphertexts,
                handshakes,
            }),
            cache: self.cache,
        })
    }

    fn decode_data(log: &Log) -> Vec<u8> {
        let tokens = decode(&[ParamType::Bytes], &log.data.0).expect("Failed to decode token.");
        let mut res = vec![];

        for token in tokens {
            res.extend_from_slice(
                &token
                    .to_bytes()
                    .expect("Failed to convert token into bytes."),
            );
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
                inputs: vec![EventParam {
                    name: "ciphertext".to_owned(),
                    kind: ParamType::Bytes,
                    indexed: false,
                }],
                anonymous: false,
            },
            Event {
                name: "StoreHandshake".to_owned(),
                inputs: vec![EventParam {
                    name: "handshake".to_owned(),
                    kind: ParamType::Bytes,
                    indexed: false,
                }],
                anonymous: false,
            },
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

/// A wrapper type of enclave logs.
#[derive(Debug)]
pub struct EnclaveLog {
    inner: Option<InnerEnclaveLog>,
    cache: Arc<RwLock<EventCache>>,
}

impl EnclaveLog {
    #[must_use]
    pub fn verify_counter(self) -> Result<Self> {
        unimplemented!();
    }

    /// Store logs into enclave in-memory.
    /// This returns a latest block number specified by fetched logs.
    pub fn insert_enclave<S: State>(self, eid: sgx_enclave_id_t) -> Result<EnclaveUpdatedState<S>> {
        match self.inner {
            Some(log) => {
                let next_blc_num = log.latest_blc_num + 1;
                let updated_states = log.invoke_ecall(eid)?;

                Ok(EnclaveUpdatedState {
                    block_num: Some(next_blc_num),
                    updated_states,
                    cache: self.cache,
                })
            }
            None => Ok(EnclaveUpdatedState {
                block_num: None,
                updated_states: None,
                cache: self.cache,
            }),
        }
    }
}

/// A log which is sent to enclave. Each log containes ciphertexts data of a given contract address and a given block number.
#[derive(Debug, Clone)]
pub struct InnerEnclaveLog {
    contract_addr: [u8; 20],
    latest_blc_num: u64,
    ciphertexts: Vec<Ciphertext>,
    handshakes: Vec<Vec<u8>>,
}

impl InnerEnclaveLog {
    pub fn invoke_ecall<S: State>(
        self,
        eid: sgx_enclave_id_t,
    ) -> Result<Option<Vec<UpdatedState<S>>>> {
        if !self.ciphertexts.is_empty() && self.handshakes.is_empty() {
            self.insert_ciphertexts(eid)
        } else if self.ciphertexts.is_empty() && !self.handshakes.is_empty() {
            // The size of handshake cannot be calculated in this host directory,
            // so the ecall_insert_handshake function is repeatedly called over the number of fetched handshakes.
            for handshake in self.handshakes {
                Self::insert_handshake(eid, handshake)?;
            }

            Ok(None)
        } else {
            debug!("No logs to insert into the enclave.");
            Ok(None)
        }
    }

    fn insert_ciphertexts<S: State>(
        self,
        eid: sgx_enclave_id_t,
    ) -> Result<Option<Vec<UpdatedState<S>>>> {
        let mut acc = vec![];

        for update in self.into_input_iter().map(
            move |inp| InsertCiphertextWorkflow::exec(inp, eid).map(|e| e.ecall_output.unwrap()), // ecall_output must be set.
        ) {
            if let Some(upd_type) = update?.updated_state {
                let upd_trait = UpdatedState::<S>::from_state_type(upd_type)?;
                acc.push(upd_trait);
            }
        }

        if acc.is_empty() {
            Ok(None)
        } else {
            Ok(Some(acc))
        }
    }

    pub fn into_input_iter(self) -> impl Iterator<Item = host_input::InsertCiphertext> {
        self.ciphertexts
            .into_iter()
            .map(host_input::InsertCiphertext::new)
    }

    fn insert_handshake(eid: sgx_enclave_id_t, handshake: Vec<u8>) -> Result<()> {
        let input = host_input::InsertHandshake::new(handshake);
        InsertHandshakeWorkflow::exec(input, eid)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct EnclaveUpdatedState<S: State> {
    block_num: Option<u64>,
    updated_states: Option<Vec<UpdatedState<S>>>,
    cache: Arc<RwLock<EventCache>>,
}

impl<S: State> EnclaveUpdatedState<S> {
    /// Only if EnclaveUpdatedState has new block number to log,
    /// it's set next block number to event cache.
    pub fn save_cache(self, contract_addr: Address) -> Self {
        match &self.block_num {
            Some(block_num) => {
                let mut w = self.cache.write();
                w.insert_next_block_num(contract_addr, *block_num);
            }
            None => {}
        }

        self
    }

    pub fn updated_states(self) -> Option<Vec<UpdatedState<S>>> {
        self.updated_states
    }
}
