use crate::eth::event_watcher::PayloadType;
use log::info;
use std::collections::{HashMap, HashSet};
use web3::types::Address as ContractAddr;

type BlockNum = u64;
type RosterIdx = u32;
type Epoch = u32;
type Generation = u32;

// TODO: overhead clone
// TODO: inner for Arc<RwLock<()>>
// Do not implement `Clone` trait due to cache duplication.
#[derive(Debug, Default)]
pub struct EventCache {
    block_num_counter: HashMap<ContractAddr, BlockNum>,
    treekem_counter: HashMap<RosterIdx, (Epoch, Generation)>,
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

    pub fn find_payload(&self, prior_payload: &PayloadType) -> Option<&PayloadType> {
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

    pub fn insert_payload_pool(&mut self, payload: PayloadType) {
        self.payload_pool.insert(payload);
    }

    pub fn update_treekem_counter(&mut self, msg: &PayloadType) {
        self.treekem_counter
            .insert(msg.roster_idx(), (msg.epoch(), msg.generation()));
    }
}
