use std::vec::Vec;
use frame_treekem::{
    GroupState, AppKeyChain, Handshake,
    handshake::{PathSecretRequest, HandshakeParams},
};
use frame_common::crypto::Ciphertext;
use frame_runtime::traits::*;
use anyhow::Result;

#[derive(Clone, Debug)]
pub struct GroupKey {
    group_state: GroupState,
    keychain: AppKeyChain,
    max_roster_idx: usize,
    path_secret_req: PathSecretRequest,
}

impl GroupKeyOps for GroupKey {
    fn new(
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

    fn create_handshake(&self) -> Result<HandshakeParams> {
        self.group_state.create_handshake(&self.path_secret_req)
    }

    fn process_handshake(
        &mut self,
        handshake: &HandshakeParams,
    ) -> Result<()> {
        let keychain = self.group_state
            .process_handshake(handshake, &self.path_secret_req, self.max_roster_idx as u32)?;
        self.keychain = keychain;

        Ok(())
    }

    fn encrypt(&self, plaintext: Vec<u8>) -> Result<Ciphertext> {
        self.keychain.encrypt_msg(plaintext, &self.group_state)
    }

    fn decrypt(&mut self, app_msg: &Ciphertext) -> Result<Option<Vec<u8>>> {
        self.keychain.decrypt_msg(&app_msg, &self.group_state)
    }

    /// Ratchet keychain per a transaction
    fn ratchet(&mut self, roster_idx: usize) -> Result<()> {
        self.keychain.ratchet(roster_idx)
    }
}
