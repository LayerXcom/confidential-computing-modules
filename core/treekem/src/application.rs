use std::vec::Vec;
use crate::group_state::GroupState;

#[derive(Clone, Debug)]
pub struct AppMsg {
    generation: u32,
    encrypted_msg: Vec<u8>,
}

pub struct AppKeyChain {

}

impl AppKeyChain {
    pub fn from_app_secret(group_state: &GroupState, ) -> Self {
        unimplemented!();
    }
}
