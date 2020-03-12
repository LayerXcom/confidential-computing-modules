use std::vec::Vec;
use std::convert::TryFrom;
use crate::group_state::GroupState;
use crate::crypto::{
    secrets::{AppSecret, AppMemberSecret, HmacKey},
    ecies::{OneNonceSequence, AES_128_GCM_KEY_SIZE, AES_128_GCM_NONCE_SIZE, AES_128_GCM_TAG_SIZE},
    hkdf, SHA256_OUTPUT_LEN,
};
use anyhow::{Result, anyhow};
use codec::Encode;
use ring::aead::{
    OpeningKey, SealingKey, Nonce, UnboundKey, BoundKey,
    Aad, AES_256_GCM,
};

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

pub struct AppKeyChain {
    member_secrets_and_gens: Vec<(AppMemberSecret, u32)>,
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

        AppKeyChain { member_secrets_and_gens }
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

    pub fn encrypt_msg(
        &mut self,
        mut plaintext: Vec<u8>,
        group_state: &GroupState
    ) -> Result<AppMsg> {
        plaintext.extend(vec![0u8; AES_128_GCM_TAG_SIZE]);
        let my_roster_index = group_state.my_roster_index();

        let (ub_key, nonce_seq, generation) = self.key_nonce_gen(my_roster_index as usize)?;
        let mut sealing_key = SealingKey::new(ub_key, nonce_seq);
        sealing_key.seal_in_place_append_tag(Aad::empty(), &mut plaintext)?;

        let ciphertext = plaintext;
        Ok(AppMsg::new(generation, group_state.epoch(), my_roster_index, ciphertext))
    }

    pub fn decrypt_msg(
        &mut self,
        mut app_msg: AppMsg,
        group_state: &GroupState,
    ) -> Result<Vec<u8>> {
        let my_roster_index = group_state.my_roster_index();
        self.ratchet(my_roster_index as usize)?;
        unimplemented!();
    }
}
