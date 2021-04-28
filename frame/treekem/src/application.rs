use crate::crypto::{
    ecies::{OneNonceSequence, AES_256_GCM_KEY_SIZE, AES_256_GCM_NONCE_SIZE},
    hkdf,
    hmac::HmacKey,
    secrets::{AppMemberSecret, AppSecret},
    SHA256_OUTPUT_LEN,
};
use crate::group_state::GroupState;
use crate::ratchet_tree::RatchetTreeNode;
use anyhow::{anyhow, ensure, Result};
use frame_common::TreeKemCiphertext;
use ring::aead::{Aad, BoundKey, Nonce, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};
use serde::Serialize;
use std::{convert::TryFrom, prelude::v1::*};
use tracing::warn;

/// Application Keychain manages each member's `AppMemberSecret' and generation.
#[derive(Debug, Clone, Default)]
pub struct AppKeyChain {
    member_secrets_and_gens: Vec<(AppMemberSecret, u32)>,
    epoch: u32,
}

impl AppKeyChain {
    /// Encrypt message with current member's application secret.
    pub fn encrypt_msg(
        &self,
        mut plaintext: Vec<u8>,
        group_state: &GroupState,
    ) -> Result<TreeKemCiphertext> {
        let my_roster_idx = group_state.my_roster_idx();

        let (ub_key, nonce_seq, generation) = self.key_nonce_gen(my_roster_idx as usize)?;
        let mut sealing_key = SealingKey::new(ub_key, nonce_seq);
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut plaintext)?;

        let ciphertext = plaintext;
        Ok(TreeKemCiphertext::new(
            generation,
            group_state.epoch(),
            my_roster_idx,
            ciphertext,
        ))
    }

    /// Decrypt message with current member's application secret.
    pub fn decrypt_msg(
        &self,
        app_msg: &TreeKemCiphertext,
        group_state: &GroupState,
    ) -> Result<Option<Vec<u8>>> {
        match group_state.my_node()? {
            // If current my node contains a DhKeypair, cannot decrypt message because you haven't join the group.
            RatchetTreeNode::Blank => {
                warn!("The received message is ignored because your enclave hasn't join the group yet");
                Ok(None)
            }
            _ => {
                ensure!(
                    app_msg.epoch() == self.epoch,
                    "The received message's epoch ({:?}) differs from the current key_chain's ({:?})",
                    app_msg.epoch(),
                    self.epoch
                );

                let (ub_key, nonce_seq, generation) =
                    self.key_nonce_gen(app_msg.roster_idx() as usize)?;
                ensure!(
                    app_msg.generation() == generation,
                    "The received message's generation ({:?}) differs from the current AppMemberSecret's ({:?})", app_msg.generation(), generation
                );

                let mut ciphertext = app_msg.encrypted_state_ref().to_vec();
                let mut opening_key = OpeningKey::new(ub_key, nonce_seq);
                let plaintext = opening_key.open_in_place(Aad::empty(), &mut ciphertext)?;

                Ok(Some(plaintext.to_vec()))
            }
        }
    }

    pub(crate) fn from_app_secret(group_state: &GroupState, app_secret: AppSecret) -> Self {
        let roster_len = match group_state.epoch() {
            0 => 1, // At the very first epoch, roster length should not be considered empty.
            _ => {
                u32::try_from(group_state.roster_len().expect("Invalid roster length"))
                    .expect("roster length exceeds u32::MAX")
                    + 1
            }
        };
        let prk = HmacKey::from(app_secret);

        let member_secrets_and_gens = (0..roster_len)
            .map(|roster_idx: u32| {
                let mut buf = vec![0u8; SHA256_OUTPUT_LEN];
                let encoded_roster_idx = bincode::serialize(&roster_idx).unwrap();
                hkdf::expand_label(&prk, b"app sender", &encoded_roster_idx, buf.as_mut_slice())
                    .expect("Failed hkdf expand.");
                let app_member_secret = AppMemberSecret::from(buf);

                (app_member_secret, 0)
            })
            .collect();

        AppKeyChain {
            member_secrets_and_gens,
            epoch: group_state.epoch(),
        }
    }

    /// Ratchets a specific roster's AppMemberSecret forward.
    pub fn ratchet(&mut self, roster_idx: usize) -> Result<()> {
        let (member_secret, gen) = self
            .member_secrets_and_gens
            .get_mut(roster_idx)
            .ok_or_else(|| {
                anyhow!("ratchet: Roster index is out of range of application key chain")
            })?;
        let current_secret = member_secret.clone();

        let roster_idx = u32::try_from(roster_idx)?;
        hkdf::expand_label(
            &current_secret.into(),
            b"app sender",
            &bincode::serialize(&roster_idx)?,
            member_secret.as_mut_bytes(),
        )?;

        *gen = gen
            .checked_add(1)
            .ok_or_else(|| anyhow!("generation is over u32::MAX"))?;

        Ok(())
    }

    pub fn generation(&self, roster_idx: usize) -> Result<u32> {
        let (_, gen) =
            self.member_secrets_and_gens
                .get(roster_idx)
                .ok_or_else(|| {
                    anyhow!("key_nonce_gen: Roster index is out of range of application key chain. roster_idx: {:?}, key chain length: {:?}", roster_idx, self.member_secrets_and_gens.len())
                })?;
        Ok(*gen)
    }

    /// Compute UnboundKey, Nonce, and member's generation.
    fn key_nonce_gen(&self, roster_idx: usize) -> Result<(UnboundKey, OneNonceSequence, u32)> {
        let (member_secret, gen) =
            self.member_secrets_and_gens
                .get(roster_idx)
                .ok_or_else(|| {
                    anyhow!("key_nonce_gen: Roster index is out of range of application key chain. roster_idx: {:?}, key chain length: {:?}", roster_idx, self.member_secrets_and_gens.len())
                })?;

        let prk = HmacKey::from(member_secret);
        let mut key_buf = [0u8; AES_256_GCM_KEY_SIZE];
        let nonce_buf = [0u8; AES_256_GCM_NONCE_SIZE];
        hkdf::expand_label(&prk, b"key", b"", &mut key_buf)?;
        hkdf::expand_label(&prk, b"nonce", b"", &mut key_buf)?;

        let ub_key = UnboundKey::new(&AES_256_GCM, &key_buf)?;
        let nonce = Nonce::assume_unique_for_key(nonce_buf);
        let nonce_seq = OneNonceSequence::new(nonce);

        Ok((ub_key, nonce_seq, *gen))
    }
}

#[cfg(debug_assertions)]
pub(crate) mod tests {
    use super::*;
    use crate::handshake::{PathSecretKVS, PathSecretSource};
    use crate::test_funcs;
    use test_utils::{runner::*, check_all_passed, run_tests};

    pub(crate) fn run_tests() -> bool {
        run_tests!(test_app_msg_correctness,)
    }

    fn test_app_msg_correctness() {
        std::env::set_var("AUDITOR_ENDPOINT", "test");
        let msg = b"app msg correctnesss test";

        let mut kvs = PathSecretKVS::new();
        test_funcs::init_path_secret_kvs(&mut kvs, 10, 10);
        let source = PathSecretSource::LocalTestKV(kvs);

        let mut group_state1 = GroupState::new(0).unwrap();
        let mut group_state2 = GroupState::new(1).unwrap();
        let mut group_state3 = GroupState::new(2).unwrap();

        // Add member1
        let (_key_chain1_epoch1, _key_chain2_epoch1, _key_chain3_epoch1) =
            test_funcs::do_handshake_three_party(
                &mut group_state1,
                &mut group_state2,
                &mut group_state3,
                &source,
            );

        // Add member2
        let (mut key_chain1_epoch1, mut key_chain2_epoch1, mut key_chain3_epoch1) =
            test_funcs::do_handshake_three_party(
                &mut group_state2,
                &mut group_state1,
                &mut group_state3,
                &source,
            );

        // 1 --> 2
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state1,
            &mut key_chain1_epoch1,
            &group_state2,
            &mut key_chain2_epoch1,
            &group_state3,
            &mut key_chain3_epoch1,
        );

        // 2 --> 1
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state2,
            &mut key_chain2_epoch1,
            &group_state1,
            &mut key_chain1_epoch1,
            &group_state3,
            &mut key_chain3_epoch1,
        );

        // 2 --> 1
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state2,
            &mut key_chain2_epoch1,
            &group_state1,
            &mut key_chain1_epoch1,
            &group_state3,
            &mut key_chain3_epoch1,
        );

        // 1 --> 2
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state1,
            &mut key_chain1_epoch1,
            &group_state2,
            &mut key_chain2_epoch1,
            &group_state3,
            &mut key_chain3_epoch1,
        );

        // Update member2
        let (mut key_chain1_epoch2, mut key_chain2_epoch2, mut key_chain3_epoch2) =
            test_funcs::do_handshake_three_party(
                &mut group_state2,
                &mut group_state1,
                &mut group_state3,
                &source,
            );

        // 1 --> 2
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state1,
            &mut key_chain1_epoch2,
            &group_state2,
            &mut key_chain2_epoch2,
            &group_state3,
            &mut key_chain3_epoch2,
        );

        // 1 --> 2
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state1,
            &mut key_chain1_epoch2,
            &group_state2,
            &mut key_chain2_epoch2,
            &group_state3,
            &mut key_chain3_epoch2,
        );

        // 2 --> 1
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state2,
            &mut key_chain2_epoch2,
            &group_state1,
            &mut key_chain1_epoch2,
            &group_state3,
            &mut key_chain3_epoch2,
        );

        // Add member3
        let (mut key_chain1_epoch3, mut key_chain2_epoch3, mut key_chain3_epoch3) =
            test_funcs::do_handshake_three_party(
                &mut group_state3,
                &mut group_state1,
                &mut group_state2,
                &source,
            );

        // 3 --> 1,2
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state3,
            &mut key_chain3_epoch3,
            &group_state1,
            &mut key_chain1_epoch3,
            &group_state2,
            &mut key_chain2_epoch3,
        );

        // 3 --> 1,2
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state3,
            &mut key_chain3_epoch3,
            &group_state1,
            &mut key_chain1_epoch3,
            &group_state2,
            &mut key_chain2_epoch3,
        );

        // 1 --> 2,3
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state1,
            &mut key_chain1_epoch3,
            &group_state2,
            &mut key_chain2_epoch3,
            &group_state3,
            &mut key_chain3_epoch3,
        );

        // 1 --> 2,3
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state1,
            &mut key_chain1_epoch3,
            &group_state2,
            &mut key_chain2_epoch3,
            &group_state3,
            &mut key_chain3_epoch3,
        );

        // update member3
        let (_key_chain1_epoch4, _key_chain2_epoch4, _key_chain3_epoch4) =
            test_funcs::do_handshake_three_party(
                &mut group_state3,
                &mut group_state1,
                &mut group_state2,
                &source,
            );

        // update member3
        let (_key_chain1_epoch5, _key_chain2_epoch5, _key_chain3_epoch5) =
            test_funcs::do_handshake_three_party(
                &mut group_state3,
                &mut group_state1,
                &mut group_state2,
                &source,
            );

        // update member1
        let (mut key_chain1_epoch6, mut key_chain2_epoch6, mut key_chain3_epoch6) =
            test_funcs::do_handshake_three_party(
                &mut group_state1,
                &mut group_state3,
                &mut group_state2,
                &source,
            );

        // 3 --> 1,2
        test_funcs::encrypt_decrypt_helper(
            msg,
            &group_state3,
            &mut key_chain3_epoch6,
            &group_state1,
            &mut key_chain1_epoch6,
            &group_state2,
            &mut key_chain2_epoch6,
        );
    }
}
