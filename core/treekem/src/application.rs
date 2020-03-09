use std::vec::Vec;
use crate::group_state::GroupState;
use crate::crypto::{AppSecret, AppMemberSecret};
use anyhow::{Result, anyhow};

#[derive(Clone, Debug)]
pub struct AppMsg {
    generation: u32,
    encrypted_msg: Vec<u8>,
}

pub struct AppKeyChain {
    member_secrets_and_gens: Vec<(AppMemberSecret, u32)>,
}

impl AppKeyChain {
    pub fn from_app_secret(group_state: &GroupState, app_secret: AppSecret) -> Self {
        unimplemented!();
    }

    pub fn encrypt_msg(
        &mut self,
        plaintext: Vec<u8>,
        group_state: &GroupState
    ) -> Result<AppMsg> {
        let my_roster_index = group_state.my_roster_index();
        unimplemented!();
    }

    pub fn decrypt_msg(
        &mut self,
        mut app_msg: AppMsg,
        group_state: &GroupState,
    ) -> Result<Vec<u8>> {
        unimplemented!();
    }
}
