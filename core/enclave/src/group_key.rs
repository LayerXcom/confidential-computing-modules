use std::vec::Vec;
use anonify_treekem::{
    GroupState, AppKeyChain, AppMsg, Handshake,
    handshake::{PathSecretRequest, HandshakeParams},
};
use anyhow::Result;
use log::info;

#[derive(Clone, Debug)]
pub struct GroupKey {
    group_state: GroupState,
    keychain: AppKeyChain,
    max_roster_idx: usize,
    path_secret_req: PathSecretRequest,
}

impl GroupKey {
    pub fn new(
        my_roster_idx: usize,
        max_roster_idx: usize,
        path_secret_req: PathSecretRequest,
    ) -> Result<Self> {
        let group_state = GroupState::new(my_roster_idx)?;
        let keychain = AppKeyChain::default();

        Ok(GroupKey {
            group_state,
            keychain,
            max_roster_idx,
            path_secret_req,
        })
    }

    pub fn create_handshake(&self) -> Result<HandshakeParams> {
        self.group_state.create_handshake(&self.path_secret_req)
    }

    pub fn process_handshake(
        &mut self,
        handshake: &HandshakeParams,
    ) -> Result<()> {
        let keychain = self.group_state
            .process_handshake(handshake, &self.path_secret_req, self.max_roster_idx as u32)?;
        self.keychain = keychain;

        Ok(())
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<AppMsg> {
        self.keychain.encrypt_msg(plaintext, &self.group_state)
    }

    pub fn decrypt(&mut self, app_msg: AppMsg) -> Result<()> {
        match self.keychain.decrypt_msg(app_msg, &self.group_state)? {
            Some(plaintext) => {

            }
            None => info!("The received message is ignored because your enclave hasn't join the group yet")
        }
        Ok(())
    }
}
