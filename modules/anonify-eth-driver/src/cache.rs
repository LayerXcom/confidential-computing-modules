use crate::eth::event_watcher::PayloadType;
use log::info;
use std::collections::{HashMap, HashSet};
use web3::types::Address as ContractAddr;

type BlockNum = u64;
type RosterIdx = u32;
type Epoch = u32;
type Generation = u32;

// TODO: Prevent malicious TEE fraudulently setting the number of trials to break consistency.
/// There are two cases where the generation of received messages is not continuous.
/// 1. In regard to the previous message, the sender's keychain ratcheted,
///    but some error occurred in the subsequent processing and it did not reach the receiver,
///    and its generation was skipped.
/// 2. The order of the received messages is changed.
///    Due to the order guarantee between network connections and the transaction order,
///    the order is changed and recorded in the message queue (blockchain).
/// In the case of 1, consistency is guaranteed between TEE node clusters,
/// so there is no problem with processing as usual.
/// In case of 2, it is necessary to process the message of
/// the next generation received later without skipping first.
/// Therefore, cache the message received earlier for a specific number of attempts shared by the cluster,
/// and wait for the message of the next generation to come.
/// If the next message does not come after waiting for the number of attempts, that message is skipped.
/// (This skip process is performed by guaranteeing consistency in all TEEs in the cluster)
const MAX_TRIALS_NUM: u32 = 10;

// TODO: overhead clone
// TODO: inner for Arc<RwLock<()>>
// Do not implement `Clone` trait due to cache duplication.
#[derive(Debug, Default)]
pub struct EventCache {
    block_num_counter: HashMap<ContractAddr, BlockNum>,
    treekem_counter: HashMap<RosterIdx, (Epoch, Generation)>,
    trials_counter: HashMap<RosterIdx, u32>,
    payload_pool: HashSet<PayloadType>,
}

impl EventCache {
    pub fn insert_next_block_num(
        &mut self,
        contract_addr: ContractAddr,
        block_num: BlockNum,
    ) -> Option<BlockNum> {
        info!("Insert: Cached block number: {}", block_num);
        self.block_num_counter.insert(contract_addr, block_num)
    }

    pub fn get_latest_block_num(&self, contract_addr: ContractAddr) -> Option<BlockNum> {
        let block_num = self.block_num_counter.get(&contract_addr).map(|e| *e);
        info!("Get: Cached block number: {:?}", block_num);
        block_num
    }

    pub fn is_next_msg(&self, msg: &PayloadType) -> bool {
        let roster_idx = msg.roster_idx();
        let (current_epoch, current_gen) = *self
            .treekem_counter
            .get(&roster_idx)
            .unwrap_or_else(|| &(0, 0));

        if msg.epoch() == current_epoch {
            msg.generation() == current_gen + 1
                || msg.generation() == 0
                || msg.generation() == u32::MAX // handshake
        } else {
            // TODO: Handling reorder over epoch
            true
        }
    }

    // TODO: Return continuous multiple payloads
    pub fn find_payload(&mut self, prior_payload: &PayloadType) -> Option<&PayloadType> {
        let traials = self
            .trials_counter
            .entry(prior_payload.roster_idx())
            .or_default();
        *traials += 1;

        if self
            .trials_counter
            .get(&prior_payload.roster_idx())
            .unwrap_or_else(|| &0)
            > &MAX_TRIALS_NUM
        {
            unimplemented!();
        } else {
            if prior_payload.generation() == u32::MAX {
                self.payload_pool
                    .iter()
                    .find(|e| e.epoch() == prior_payload.epoch() + 1 && e.generation() == 0)
            } else {
                self.payload_pool.iter().find(|e| {
                    e.epoch() == prior_payload.epoch()
                        && e.generation() == prior_payload.generation() + 1
                })
            }
        }
    }

    pub fn insert_payload_pool(&mut self, payload: PayloadType) {
        self.payload_pool.insert(payload);
    }

    pub fn update_treekem_counter(&mut self, msg: &PayloadType) {
        self.treekem_counter
            .insert(msg.roster_idx(), (msg.epoch(), msg.generation()));
    }
}
