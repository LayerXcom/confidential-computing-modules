use anyhow::{anyhow, Result};
use frame_common::crypto::{Ciphertext, ExportHandshake, ExportPathSecret};
use frame_runtime::traits::*;
use frame_treekem::{
    handshake::{HandshakeParams, PathSecretSource},
    AppKeyChain, GroupState, Handshake,
};
use log::warn;
use std::vec::Vec;

#[derive(Clone, Debug)]
pub struct GroupKey {
    group_state: GroupState,
    sender_keychain: AppKeyChain,
    receiver_keychain: AppKeyChain,
    max_roster_idx: usize,
    source: PathSecretSource,
}

impl GroupKey {
    pub fn new(
        my_roster_idx: usize,
        max_roster_idx: usize,
        source: PathSecretSource,
    ) -> Result<Self> {
        let group_state = GroupState::new(my_roster_idx)?;
        let sender_keychain = AppKeyChain::default();
        let receiver_keychain = sender_keychain.clone();

        Ok(GroupKey {
            group_state,
            sender_keychain,
            receiver_keychain,
            max_roster_idx,
            source,
        })
    }
}

impl GroupKeyOps for GroupKey {
    fn create_handshake(&self) -> Result<(ExportHandshake, ExportPathSecret)> {
        let (handshake, exp_ps) = self.group_state.create_handshake(&self.source)?;
        Ok((handshake.into_export(), exp_ps))
    }

    fn process_handshake(&mut self, handshake: &HandshakeParams) -> Result<()> {
        let keychain = self.group_state.process_handshake(
            handshake,
            &self.source,
            self.max_roster_idx as u32,
            frame_enclave::ocalls::import_path_secret,
        )?;
        // TODO: If the handshake transaction is flying out the air, wait updating the sender_keychain until the all remaining messages are proccessed.
        // The number of remaining messages are difference between sender_keychain's generation and receiver_keychain's one.
        self.sender_keychain = keychain.clone();
        self.receiver_keychain = keychain;

        Ok(())
    }

    fn encrypt(&self, plaintext: Vec<u8>) -> Result<Ciphertext> {
        self.sender_keychain
            .encrypt_msg(plaintext, &self.group_state)
    }

    fn decrypt(&self, app_msg: &Ciphertext) -> Result<Option<Vec<u8>>> {
        self.receiver_keychain
            .decrypt_msg(&app_msg, &self.group_state)
    }

    /// Ratchet sender's keychain per a transaction
    fn sender_ratchet(&mut self, roster_idx: usize) -> Result<()> {
        self.sender_keychain.ratchet(roster_idx)
    }

    /// Ratchet receiver's keychain per a transaction
    fn receiver_ratchet(&mut self, roster_idx: usize) -> Result<()> {
        self.receiver_keychain.ratchet(roster_idx)
    }

    /// Syncing the sender and receiver app keychains
    fn sync_ratchet(&mut self, roster_idx: usize) -> Result<()> {
        match self
            .sender_keychain
            .generation(roster_idx)?
            .checked_sub(self.receiver_keychain.generation(roster_idx)?)
        {
            // syncing the sender and receiver app keychains
            Some(0) => self.sender_ratchet(roster_idx),
            // It's okay if the sender generation is bigger than receiver's.
            // If an error occurs after ratcheting the sender's keychain,
            // the generation of the received message will be discontinuous,
            // so ratchet the receiver's keychain by the difference in order to be consistent.
            Some(diff) => {
                warn!(
                    "the generation of the received message will be discontinuous, so ratchet the receiver's keychain by {:?} times",
                    diff - 1
                );
                if diff - 1 > 0 {
                    for _ in 0..diff {
                        self.receiver_ratchet(roster_idx)?;
                    }
                }

                Ok(())
            }
            // It's an error case if the receiver generation is bigger than sender's
            None => Err(anyhow!(
                "receiver generation must not be bigger than sender's one"
            )),
        }
    }

    fn my_roster_idx(&self) -> u32 {
        self.group_state.my_roster_idx()
    }
}
