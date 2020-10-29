use super::connection::{Web3Contract, Web3Http};
use crate::{
    cache::{EventCache, MAX_TRIALS_NUM},
    error::{HostError, Result},
    traits::*,
    utils::*,
    workflow::*,
};
use anyhow::anyhow;
use async_trait::async_trait;
use codec::Decode;
use ethabi::{decode, Event, EventParam, Hash, ParamType};
use frame_common::{
    crypto::{Ciphertext, ExportHandshake},
    state_types::UpdatedState,
    traits::*,
};
use frame_host::engine::HostEngine;
use log::{debug, error, warn};
use sgx_types::sgx_enclave_id_t;
use std::{cmp::Ordering, path::Path};
use web3::types::{Address, Log};

/// Components needed to watch events
pub struct EventWatcher {
    contract: Web3Contract,
    cache: EventCache,
}

#[async_trait]
impl Watcher for EventWatcher {
    fn new<P: AsRef<Path>>(
        node_url: &str,
        contract_info: ContractInfo<'_, P>,
        cache: EventCache,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info)?;

        Ok(EventWatcher { contract, cache })
    }

    /// Fetch events of the specified topics on the blockchain.
    /// This method is supposed to be called for polling.
    /// If an error occurs in the process of updating the status due to the fetched events,
    /// that events will be skipped. (No retry process)
    /// If an error occurs on all TEE nodes due to an invalid event etc., skip processing is okay.
    async fn fetch_events<S: State>(
        &self,
        eid: sgx_enclave_id_t,
    ) -> Result<Option<Vec<UpdatedState<S>>>> {
        let enclave_updated_state = self
            .contract
            .get_event(self.cache.clone(), self.contract.address())
            .await?
            .into_enclave_log()
            .insert_enclave(eid)
            .save_cache(self.contract.address());

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
    cache: EventCache,
    events: EthEvent,
}

impl Web3Logs {
    pub fn new(logs: Vec<Log>, cache: EventCache, events: EthEvent) -> Self {
        Web3Logs {
            logs,
            cache,
            events,
        }
    }

    fn into_enclave_log(self) -> EnclaveLog {
        let mut payloads: Vec<PayloadType> = vec![];

        // If log data is not fetched, return empty EnclaveLog.
        // This is occurred when it fetched data of dupulicated block number.
        if self.logs.is_empty() {
            return EnclaveLog {
                inner: None,
                cache: self.cache,
            };
        }

        let contract_addr = self.logs[0].address;
        let mut latest_blc_num = 0;

        for (i, log) in self.logs.iter().enumerate() {
            debug!("Inserting enclave log: {:?}, \nindex: {:?}", log, i);
            if contract_addr != log.address {
                error!("Each log should have same contract address.: index: {}", i);
                continue;
            }

            let data = match decode_data(&log) {
                Ok(d) => d,
                Err(e) => {
                    error!("{}", e);
                    continue;
                }
            };

            // Processing conditions by ciphertext or handshake event
            if log.topics[0] == self.events.ciphertext_signature() {
                let res = match Ciphertext::decode(&mut &data[..]) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("{}", e);
                        continue;
                    }
                };
                let payload = PayloadType::new(
                    res.roster_idx(),
                    res.epoch(),
                    res.generation(),
                    Payload::Ciphertext(res),
                );
                payloads.push(payload);
            } else if log.topics[0] == self.events.handshake_signature() {
                let res = match ExportHandshake::decode(&mut &data[..]) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("{}", e);
                        continue;
                    }
                };
                let payload = PayloadType::new(
                    res.roster_idx(),
                    res.prior_epoch(),
                    u32::MAX, // handshake is the last of the generation
                    Payload::Handshake(res),
                );
                payloads.push(payload);
            } else {
                error!("Invalid topics: {:?}", log.topics[0]);
                continue;
            }

            // Update latest block number
            if let Some(blc_num) = log.block_number {
                let blc_num = blc_num.as_u64();
                if latest_blc_num < blc_num {
                    latest_blc_num = blc_num
                }
            }
        }

        // Reordered by the priority in all fetched payloads
        payloads.sort();
        // Removes consecutive repeated message
        payloads.dedup();
        // Order guarantee
        let immutable_payloads = payloads.clone();
        let payloads = {
            let mut mut_cache = self.cache.inner().write();
            mut_cache.ensure_order_guarantee(payloads, immutable_payloads, MAX_TRIALS_NUM)
        };

        EnclaveLog {
            inner: Some(InnerEnclaveLog {
                contract_addr: contract_addr.to_fixed_bytes(),
                latest_blc_num,
                payloads,
                logs: self.logs,
            }),
            cache: self.cache,
        }
    }
}

/// A wrapper type of enclave logs.
#[derive(Debug)]
struct EnclaveLog {
    inner: Option<InnerEnclaveLog>,
    cache: EventCache,
}

impl EnclaveLog {
    /// Store logs into enclave in-memory.
    /// This returns a latest block number specified by fetched logs.
    fn insert_enclave<S: State>(self, eid: sgx_enclave_id_t) -> EnclaveUpdatedState<S> {
        match self.inner {
            Some(log) => {
                let next_blc_num = log.latest_blc_num + 1;
                let updated_states = log.invoke_ecall(eid);

                EnclaveUpdatedState {
                    block_num: Some(next_blc_num),
                    updated_states,
                    cache: self.cache,
                }
            }
            None => EnclaveUpdatedState {
                block_num: None,
                updated_states: None,
                cache: self.cache,
            },
        }
    }
}

/// A log which is sent to enclave. Each log containes ciphertexts data of a given contract address and a given block number.
#[derive(Debug, Clone)]
struct InnerEnclaveLog {
    contract_addr: [u8; 20],
    latest_blc_num: u64,
    payloads: Vec<PayloadType>,
    logs: Vec<Log>,
}

impl InnerEnclaveLog {
    fn invoke_ecall<S: State>(self, eid: sgx_enclave_id_t) -> Option<Vec<UpdatedState<S>>> {
        if self.payloads.is_empty() {
            debug!("No logs to insert into the enclave.");
            None
        } else {
            let mut acc = vec![];

            for e in self.payloads {
                match e.payload {
                    Payload::Ciphertext(ciphertext) => {
                        debug!(
                            "Fetch a ciphertext: roster_idx: {}, epoch: {}, generation: {}",
                            ciphertext.roster_idx(),
                            ciphertext.epoch(),
                            ciphertext.generation()
                        );

                        let inp = host_input::InsertCiphertext::new(ciphertext.clone());
                        match InsertCiphertextWorkflow::exec(inp, eid)
                            .map_err(Into::into)
                            .and_then(|e| {
                                e.ecall_output.ok_or_else(|| HostError::EcallOutputNotSet)
                            }) {
                            Ok(update) => {
                                if let Some(upd_type) = update.updated_state {
                                    match UpdatedState::<S>::from_state_type(upd_type) {
                                        Ok(upd_trait) => acc.push(upd_trait),
                                        Err(err) => {
                                            error!("{:?}", err);
                                            continue;
                                        }
                                    }
                                }
                            }
                            // Even if an error occurs in Enclave, it is unlikely that retry process will succeed,
                            // so skip the event.
                            Err(err) => {
                                error!(
                                    "Error in enclave (InsertCiphertextWorkflow::exec): {:?}",
                                    err
                                );

                                // Logging a skipped event
                                match (&self.logs)
                                    .into_iter()
                                    .find(|log| match decode_data(&log) {
                                        Ok(data) => match Ciphertext::decode(&mut &data[..]) {
                                            Ok(res) => res == ciphertext,
                                            Err(error) => {
                                                error!("Ciphertext::decode error: {:?}", error);
                                                false
                                            }
                                        },
                                        Err(error) => {
                                            error!("decode_data error: {:?}", error);
                                            false
                                        }
                                    }) {
                                    Some(skipped_log) => {
                                        warn!(
                                            "A event is skipped because of occurring error in enclave: {:?}",
                                            skipped_log
                                        )
                                    }
                                    None => {
                                        error!(
                                            "Not found the skipped event. The corresponding ciphertext is {:?}",
                                            ciphertext
                                        );
                                    }
                                }

                                continue;
                            }
                        };
                    }
                    Payload::Handshake(handshake) => {
                        debug!(
                            "Fetch a handshake: roster_idx: {}, epoch: {}",
                            handshake.roster_idx(),
                            handshake.prior_epoch(),
                        );

                        if let Err(e) = Self::insert_handshake(eid, handshake) {
                            error!("Error in enclave (InsertHandshakeWorkflow::exec): {:?}", e);
                            continue;
                        }
                    }
                }
            }

            if acc.is_empty() {
                None
            } else {
                Some(acc)
            }
        }
    }

    fn insert_handshake(eid: sgx_enclave_id_t, handshake: ExportHandshake) -> Result<()> {
        let input = host_input::InsertHandshake::new(handshake);
        InsertHandshakeWorkflow::exec(input, eid)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct EnclaveUpdatedState<S: State> {
    block_num: Option<u64>,
    updated_states: Option<Vec<UpdatedState<S>>>,
    cache: EventCache,
}

impl<S: State> EnclaveUpdatedState<S> {
    /// Only if EnclaveUpdatedState has new block number to log,
    /// it's set next block number to event cache.
    pub fn save_cache(self, contract_addr: Address) -> Self {
        match &self.block_num {
            Some(block_num) => {
                let mut w = self.cache.inner().write();
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

#[derive(Debug, Clone, Hash)]
pub struct PayloadType {
    roster_idx: u32,
    epoch: u32,
    generation: u32,
    payload: Payload,
}

impl PayloadType {
    pub(crate) fn new(roster_idx: u32, epoch: u32, generation: u32, payload: Payload) -> Self {
        PayloadType {
            roster_idx,
            epoch,
            generation,
            payload,
        }
    }

    /// other is the next of self
    pub fn is_next(&self, other: &Self) -> bool {
        self.roster_idx == other.roster_idx
            && ((self.epoch == other.epoch && self.generation + 1 == other.generation) ||
            (self.epoch == other.epoch && other.generation == u32::MAX) || // TODO: order gurantee with handshake
            (self.epoch + 1 == other.epoch && self.generation == u32::MAX && other.generation == 0))
    }

    pub fn roster_idx(&self) -> u32 {
        self.roster_idx
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }
}

impl PartialEq for PayloadType {
    fn eq(&self, other: &PayloadType) -> bool {
        self.roster_idx == other.roster_idx
            && self.epoch == other.epoch
            && self.generation == other.generation
    }
}

impl Eq for PayloadType {}

/// Ordering PayloadType> like:
/// epoch      | 0              1            2 ..
/// generation | 0 1 2 3 .. MAX 0 1 2 .. MAX 0 ..
impl PartialOrd for PayloadType {
    fn partial_cmp(&self, other: &PayloadType) -> Option<Ordering> {
        let roster_idx_ord = self.roster_idx.partial_cmp(&other.roster_idx)?;
        if roster_idx_ord != Ordering::Equal {
            return Some(roster_idx_ord);
        }

        let epoch_ord = self.epoch.partial_cmp(&other.epoch)?;
        if epoch_ord != Ordering::Equal {
            return Some(epoch_ord);
        }

        let gen_ord = self.generation.partial_cmp(&other.generation)?;
        if gen_ord != Ordering::Equal {
            return Some(gen_ord);
        }

        Some(Ordering::Equal)
    }
}

impl Ord for PayloadType {
    fn cmp(&self, other: &PayloadType) -> Ordering {
        self.partial_cmp(&other)
            .expect("PayloadType must be ordered")
    }
}

#[derive(Debug, Clone, Hash)]
pub(crate) enum Payload {
    Ciphertext(Ciphertext),
    Handshake(ExportHandshake),
}

impl Default for Payload {
    fn default() -> Self {
        Payload::Ciphertext(Default::default())
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

fn decode_data(log: &Log) -> Result<Vec<u8>> {
    let tokens = decode(&[ParamType::Bytes], &log.data.0)?;
    let mut res = vec![];

    for token in tokens {
        res.extend_from_slice(
            &token
                .to_bytes()
                .ok_or_else(|| anyhow!("Failed token.to_bytes() when decoding data"))?,
        );
    }

    Ok(res)
}
