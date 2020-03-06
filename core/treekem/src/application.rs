use std::vec::Vec;
use crate::group_state::GroupState;
use crate::crypto::AppSecret;

#[derive(Clone, Debug)]
pub struct AppMsg {
    generation: u32,
    encrypted_msg: Vec<u8>,
}

pub struct AppKeyChain {

}

impl AppKeyChain {
    pub fn from_app_secret(group_state: &GroupState, app_secret: AppSecret) -> Self {
        unimplemented!();
    }
}
