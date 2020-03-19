use std::vec::Vec;
use std::convert::TryFrom;
use crate::group_state::GroupState;
use crate::crypto::{
    hmac::HmacKey,
    secrets::{AppSecret, AppMemberSecret},
    ecies::{OneNonceSequence, AES_128_GCM_KEY_SIZE, AES_128_GCM_NONCE_SIZE, AES_128_GCM_TAG_SIZE},
    hkdf, SHA256_OUTPUT_LEN,
};
use anyhow::{Result, anyhow, ensure};
use codec::Encode;
use ring::aead::{
    OpeningKey, SealingKey, Nonce, UnboundKey, BoundKey,
    Aad, AES_256_GCM,
};

/// Application message broadcasted to other members.
#[derive(Clone, Debug)]
pub struct AppMsg {
    generation: u32,
    epoch: u32,
    roster_idx: u32,
    encrypted_msg: Vec<u8>,
}

impl AppMsg {
    pub fn new(generation: u32, epoch: u32, roster_idx: u32, encrypted_msg: Vec<u8>) -> Self {
        AppMsg { generation, epoch, roster_idx, encrypted_msg }
    }
}

/// Application Keychain manages each member's `AppMemberSecret' and generation.
pub struct AppKeyChain {
    member_secrets_and_gens: Vec<(AppMemberSecret, u32)>,
    epoch: u32,
}

impl AppKeyChain {
    pub fn from_app_secret(group_state: &GroupState, app_secret: AppSecret) -> Self {
        let roster_len = u32::try_from(group_state.roster_len().expect("Invalid roster length"))
                .expect("roster length exceeds u32::MAX");
        let prk = HmacKey::from(app_secret);

        let member_secrets_and_gens = (0..roster_len).map(|roster_idx: u32| {
            let mut buf = vec![0u8; SHA256_OUTPUT_LEN];
            let encoded_roster_idx = roster_idx.encode();
            hkdf::expand_label(
                &prk,
                b"app sender",
                &encoded_roster_idx,
                buf.as_mut_slice(),
            )
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

    /// Encrypt message with current member's application secret.
    pub fn encrypt_msg(
        &mut self,
        mut plaintext: Vec<u8>,
        group_state: &GroupState
    ) -> Result<AppMsg> {
        plaintext.extend(vec![0u8; AES_128_GCM_TAG_SIZE]);
        let my_roster_idx = group_state.my_roster_idx();

        let (ub_key, nonce_seq, generation) = self.key_nonce_gen(my_roster_idx as usize)?;
        let mut sealing_key = SealingKey::new(ub_key, nonce_seq);
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut plaintext)?;

        let ciphertext = plaintext;
        Ok(AppMsg::new(generation, group_state.epoch(), my_roster_idx, ciphertext))
    }

    /// Decrypt messag with current member's application secret.
    pub fn decrypt_msg(
        &mut self,
        mut app_msg: AppMsg,
        group_state: &GroupState,
    ) -> Result<Vec<u8>> {
        ensure!(app_msg.epoch == self.epoch, "application messages's epoch differs from the app key chain's");

        let (ub_key, nonce_seq, generation) = self.key_nonce_gen(app_msg.roster_idx as usize)?;
        ensure!(app_msg.generation == generation, "application messages's generation differs from the AppMmeberSecret's");

        let mut plaintext = app_msg.encrypted_msg.clone();
        let mut opening_key = OpeningKey::new(ub_key, nonce_seq);
        opening_key.open_in_place(Aad::empty(), &mut plaintext)?;

        self.ratchet(app_msg.roster_idx as usize)?;
        Ok(plaintext)
    }

    /// Ratchets a specific roster's AppMemberSecret forward.
    fn ratchet(&mut self, roster_idx: usize) -> Result<()> {
        let (member_secret, gen) = self.member_secrets_and_gens
            .get_mut(roster_idx)
            .ok_or(anyhow!("Roster index is out of range of application key chain"))?;
        let current_secret = member_secret.clone();

        let roster_idx = u32::try_from(roster_idx)?;
        hkdf::expand_label(
            &current_secret.into(),
            b"app sender",
            &roster_idx.encode(),
            member_secret.as_mut_bytes(),
        )?;

        *gen = gen.checked_add(1).ok_or(anyhow!("geenration is over u32::MAX"))?;

        Ok(())
    }

    /// Compute UnboundKey, Nonce, and member's generation.
    fn key_nonce_gen(&self, roster_idx: usize) -> Result<(UnboundKey, OneNonceSequence, u32)> {
        let (member_secret, gen) = self.member_secrets_and_gens
            .get(roster_idx)
            .ok_or(anyhow!("Roster index is out of range of application key chain"))?;

        let prk = HmacKey::from(member_secret);
        let mut key_buf = [0u8; AES_128_GCM_KEY_SIZE];
        let mut nonce_buf = [0u8; AES_128_GCM_NONCE_SIZE];
        hkdf::expand_label(&prk, b"key", b"", &mut key_buf)?;
        hkdf::expand_label(&prk, b"nonce", b"", &mut key_buf)?;

        let ub_key = UnboundKey::new(&AES_256_GCM, &key_buf)?;
        let nonce = Nonce::assume_unique_for_key(nonce_buf);
        let nonce_seq = OneNonceSequence::new(nonce);

        Ok((ub_key, nonce_seq, *gen))
    }
}

#[cfg(debug_assertions)]
pub mod test {
    use super::*;
    use crate::test_utils;
    use rand::{self, SeedableRng};

    fn encrypt_decrypt_helper(
        msg: &[u8],
        group1: &GroupState,
        app_key_chain1: &mut AppKeyChain,
        group2: &GroupState,
        app_key_chain2: &mut AppKeyChain,
    ) {
        let app_msg = app_key_chain1.encrypt_msg(msg.to_vec(), group1).unwrap();
        let plaintext = app_key_chain2.decrypt_msg(app_msg, group2).unwrap();

        assert_eq!(plaintext.as_slice(), msg);
    }

    pub fn app_msg_correctness() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let msg = b"app msg correctnesss test";
        let mut group_state1 = test_utils::random_group_state();

        let new_roster_idx = 1;
        let mut group_state2 = test_utils::change_group_state_idx(&group_state1, new_roster_idx);

        // encrypt_decrypt_helper(
        //     msg,
        // )
    }
}
