use super::connection::{Web3Contract, Web3Http};
use crate::{
    cache::EventCache,
    error::{HostError, Result},
    utils::*,
    workflow::*,
};
use ethabi::{decode, Event, EventParam, Hash, ParamType};
use frame_common::{
    crypto::{Ciphertext, ExportHandshake},
    state_types::StateCounter,
};
use frame_host::engine::HostEngine;
use sgx_types::sgx_enclave_id_t;
use std::{cmp::Ordering, fmt};
use tracing::{debug, error, info, warn};
use web3::types::{Address, Log};

/// Components needed to watch events
#[derive(Debug)]
pub struct EventWatcher {
    contract: Web3Contract,
    cache: EventCache,
}

impl EventWatcher {
    pub fn new(node_url: &str, contract_info: ContractInfo, cache: EventCache) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info)?;

        Ok(EventWatcher { contract, cache })
    }

    /// Fetch events of the specified topics on the blockchain.
    /// This method is supposed to be called for polling.
    /// If an error occurs in the process of updating the status due to the fetched events,
    /// that events will be skipped. (No retry process)
    /// If an error occurs on all TEE nodes due to an invalid event etc., skip processing is okay.
    pub async fn fetch_events(
        &self,
        eid: sgx_enclave_id_t,
        fetch_ciphertext_cmd: u32,
        fetch_handshake_cmd: u32,
    ) -> Result<Option<Vec<serde_json::Value>>> {
        let enclave_updated_state = self
            .contract
            .get_event(self.cache.clone(), self.contract.address())
            .await?
            .into_enclave_log()
            .insert_enclave(eid, fetch_ciphertext_cmd, fetch_handshake_cmd)
            .save_cache(self.contract.address());

        Ok(enclave_updated_state.notify_states())
    }

    pub fn get_contract(self) -> Web3Contract {
        self.contract
    }
}

#[derive(Clone)]
struct EthLog(Log);

impl From<Log> for EthLog {
    fn from(log: Log) -> Self {
        EthLog(log)
    }
}

impl fmt::Debug for EthLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::LowerHex for EthLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EthLog {{ address: {:?}, data: 0x{}, block_hash: {:?}, block_number: {:?}, transaction_hash: {:?}, transaction_index: {:?}, log_index: {:?}, transaction_log_index: {:?}, log_type: {:?}, removed: {:?} }}",
            self.0.address,
            hex::encode(&self.0.data.0),
            self.0.block_hash,
            self.0.block_number,
            self.0.transaction_hash,
            self.0.transaction_index,
            self.0.log_index,
            self.0.transaction_log_index,
            self.0.log_type,
            self.0.removed
        )
    }
}

/// Event fetched logs from smart contracts.
#[derive(Debug)]
pub struct Web3Logs {
    logs: Vec<EthLog>,
    cache: EventCache,
    events: EthEvent,
}

impl Web3Logs {
    pub fn new(logs: Vec<Log>, cache: EventCache, events: EthEvent) -> Self {
        let logs: Vec<EthLog> = logs.into_iter().map(Into::into).collect();
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

        let contract_addr = self.logs[0].0.address;
        let mut latest_blc_num = 0;

        for (i, log) in self.logs.iter().enumerate() {
            info!(
                "Fetched eth event log: {:?}, \npolling event index: {:?}",
                log, i
            );
            if contract_addr != log.0.address {
                error!("Each log should have same contract address.: index: {}", i);
                continue;
            }

            let (bytes, state_counter) = match decode_data(&log) {
                Ok(d) => d,
                Err(e) => {
                    error!("{}", e);
                    continue;
                }
            };

            // Processing conditions by ciphertext or handshake event
            if log.0.topics[0] == self.events.ciphertext_signature() {
                let res = match Ciphertext::decode(&mut &bytes[..]) {
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
                    state_counter,
                );
                payloads.push(payload);
            } else if log.0.topics[0] == self.events.handshake_signature() {
                let res = match ExportHandshake::decode(&bytes[..]) {
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
                    state_counter,
                );
                payloads.push(payload);
            } else {
                error!("Invalid topics: {:?}", log.0.topics[0]);
                continue;
            }

            // Update latest block number
            if let Some(blc_num) = log.0.block_number {
                let blc_num = blc_num.as_u64();
                if latest_blc_num < blc_num {
                    latest_blc_num = blc_num
                }
            }
        }

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
    fn insert_enclave(
        self,
        eid: sgx_enclave_id_t,
        fetch_ciphertext_cmd: u32,
        fetch_handshake_cmd: u32,
    ) -> EnclaveUpdatedState {
        match self.inner {
            Some(log) => {
                let next_blc_num = log.latest_blc_num + 1;
                let notify_states =
                    log.invoke_ecall(eid, fetch_ciphertext_cmd, fetch_handshake_cmd);

                EnclaveUpdatedState {
                    block_num: Some(next_blc_num),
                    notify_states,
                    cache: self.cache,
                }
            }
            None => EnclaveUpdatedState {
                block_num: None,
                notify_states: None,
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
    logs: Vec<EthLog>,
}

impl InnerEnclaveLog {
    fn invoke_ecall(
        self,
        eid: sgx_enclave_id_t,
        fetch_ciphertext_cmd: u32,
        fetch_handshake_cmd: u32,
    ) -> Option<Vec<serde_json::Value>> {
        if self.payloads.is_empty() {
            debug!("No logs to insert into the enclave.");
            None
        } else {
            let mut acc = vec![];

            for e in self.payloads {
                match e.payload {
                    Payload::Ciphertext(ref ciphertext) => {
                        info!(
                            "Fetch a ciphertext: roster_idx: {}, epoch: {}, generation: {}",
                            ciphertext.roster_idx(),
                            ciphertext.epoch(),
                            ciphertext.generation()
                        );

                        let inp = host_input::InsertCiphertext::new(
                            ciphertext.clone(),
                            e.state_counter(),
                            fetch_ciphertext_cmd,
                        );
                        match InsertCiphertextWorkflow::exec(inp, eid)
                            .map_err(Into::into)
                            .and_then(|e| {
                                e.ecall_output.ok_or_else(|| HostError::EcallOutputNotSet)
                            }) {
                            Ok(notify) => {
                                if let Some(notify_state) = notify.state {
                                    match bincode::deserialize::<Vec<u8>>(
                                        &notify_state.into_vec()[..],
                                    ) {
                                        Ok(bytes) => match serde_json::from_slice(&bytes[..]) {
                                            Ok(json) => acc.push(json),
                                            Err(err) => error!(
                                                "Error in serde_json::from_slice(&bytes[..]): {:?}",
                                                err
                                            ),
                                        },
                                        Err(err) => {
                                            error!("Error in bincode::deserialize: {:?}", err)
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
                                        Ok((bytes, _state_counter)) => match Ciphertext::decode(&mut &bytes[..]) {
                                            Ok(ref res) => res == ciphertext,
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
                    Payload::Handshake(ref handshake) => {
                        info!(
                            "Fetch a handshake: roster_idx: {}, epoch: {}",
                            handshake.roster_idx(),
                            handshake.prior_epoch(),
                        );

                        if let Err(e) = Self::insert_handshake(
                            eid,
                            handshake.clone(),
                            e.state_counter(),
                            fetch_handshake_cmd,
                        ) {
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

    fn insert_handshake(
        eid: sgx_enclave_id_t,
        handshake: ExportHandshake,
        state_counter: StateCounter,
        fetch_handshake_cmd: u32,
    ) -> Result<()> {
        let input = host_input::InsertHandshake::new(handshake, state_counter, fetch_handshake_cmd);
        InsertHandshakeWorkflow::exec(input, eid)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct EnclaveUpdatedState {
    block_num: Option<u64>,
    notify_states: Option<Vec<serde_json::Value>>,
    cache: EventCache,
}

impl EnclaveUpdatedState {
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

    pub fn notify_states(self) -> Option<Vec<serde_json::Value>> {
        self.notify_states
    }
}

#[derive(Debug, Clone, Hash)]
pub struct PayloadType {
    roster_idx: u32,
    epoch: u32,
    generation: u32,
    payload: Payload,
    state_counter: StateCounter,
}

impl PayloadType {
    pub(crate) fn new(
        roster_idx: u32,
        epoch: u32,
        generation: u32,
        payload: Payload,
        state_counter: StateCounter,
    ) -> Self {
        PayloadType {
            roster_idx,
            epoch,
            generation,
            payload,
            state_counter,
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

    pub fn state_counter(&self) -> StateCounter {
        self.state_counter
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
                inputs: vec![
                    EventParam {
                        name: "ciphertext".to_owned(),
                        kind: ParamType::Bytes,
                        indexed: true,
                    },
                    EventParam {
                        name: "stateCounter".to_owned(),
                        kind: ParamType::Uint(256),
                        indexed: true,
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
                        indexed: true,
                    },
                    EventParam {
                        name: "stateCounter".to_owned(),
                        kind: ParamType::Uint(256),
                        indexed: true,
                    },
                ],
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

fn decode_data(log: &EthLog) -> Result<(Vec<u8>, StateCounter)> {
    let tokens = decode(&[ParamType::Bytes, ParamType::Uint(256)], &log.0.data.0)?;
    if tokens.len() != 2 {
        return Err(HostError::InvalidNumberOfEthLogToken(2));
    }
    let bytes = tokens[0]
        .clone()
        .to_bytes()
        .ok_or_else(|| HostError::InvalidEthLogToken)?;
    let state_counter = tokens[1]
        .clone()
        .to_uint()
        .ok_or_else(|| HostError::InvalidEthLogToken)?;

    Ok((bytes, StateCounter::new(state_counter.as_u32())))
}
