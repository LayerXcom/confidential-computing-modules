use frame_common::crypto::Ciphertext;
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
    ciphertext_pool: HashSet<Ciphertext>,
}

impl EventCache {
    pub fn insert_next_block_num(
        &mut self,
        contract_addr: ContractAddr,
        block_num: BlockNum,
    ) -> Option<BlockNum> {
        self.block_num_counter.insert(contract_addr, block_num)
    }

    pub fn get_latest_block_num(&self, contract_addr: ContractAddr) -> Option<BlockNum> {
        self.block_num_counter.get(&contract_addr).map(|e| *e)
    }

    // TODO: Handling reorder over epoch is not solved yet.
    pub fn is_next_msg(&self, msg: Ciphertext) -> bool {
        // let roster_idx = msg.roster_idx();
        // let (current_epoch, current_gen) = self.treekem_counter.get(&roster_idx).unwrap_or_default();

        // if msg.epoch() == current_epoch {
        //     msg.generation() == current_gen + 1 || msg.generation() == 0
        // } else {
        //     msg.generation() == 0
        // }
        unimplemented!();
    }

    pub fn update_treekem_counter(&self, msg: Ciphertext) {
        // self.treekem_counter.insert(msg.roster_idx(), (msg.epoch(), msg.generation()));
    }

    pub fn insert_ciphertext_pool(&self, ciphertext: Ciphertext) {
        // self.ciphertext_pool.insert(ciphertext);
    }

    pub fn find_ciphertext_pool(&self, ciphertext: Ciphertext) {
        unimplemented!();
    }
}
