use frame_common::crypto::Ciphertext;
use std::collections::{HashMap, HashSet};
use web3::types::Address as ContractAddr;
use log::info;

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
    ciphertext_pool: HashSet<Ciphertext>,
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

    pub fn is_next_msg(&self, msg: Ciphertext) -> bool {
        let roster_idx = msg.roster_idx();
        let (current_epoch, current_gen) = *self
            .treekem_counter
            .get(&roster_idx)
            .unwrap_or_else(|| &(0, 0));

        if msg.epoch() == current_epoch {
            msg.generation() == current_gen + 1 || msg.generation() == 0
        } else {
            // TODO: Handling reorder over epoch
            true
        }
    }

    pub fn update_treekem_counter(&mut self, msg: Ciphertext) {
        self.treekem_counter
            .insert(msg.roster_idx(), (msg.epoch(), msg.generation()));
    }

    pub fn insert_ciphertext_pool(&mut self, ciphertext: Ciphertext) {
        self.ciphertext_pool.insert(ciphertext);
    }

    pub fn find_ciphertext(&self, id: (Epoch, Generation)) -> Option<&Ciphertext> {
        self.ciphertext_pool
            .iter()
            .find(|e| e.epoch() == id.0 && e.generation() == id.1)
    }
}
