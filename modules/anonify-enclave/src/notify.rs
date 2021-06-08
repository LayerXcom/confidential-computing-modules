use anonify_ecall_types::cmd::REGISTER_NOTIFICATION_CMD;
use anonify_ecall_types::*;
use frame_common::{crypto::AccountId, state_types::StateType, AccessPolicy};
use frame_enclave::StateRuntimeEnclaveUseCase;
use frame_runtime::traits::*;
use frame_sodium::SodiumCiphertext;
use std::{
    collections::HashSet,
    sync::{Arc, SgxRwLock},
};

#[derive(Debug, Clone)]
pub struct Notifier {
    account_ids: Arc<SgxRwLock<HashSet<AccountId>>>,
}

impl Notifier {
    pub fn new() -> Self {
        let account_ids = HashSet::new();
        Notifier {
            account_ids: Arc::new(SgxRwLock::new(account_ids)),
        }
    }

    pub fn register(&self, account_id: AccountId) -> bool {
        let mut tmp = self.account_ids.write().unwrap();
        tmp.insert(account_id)
    }

    pub fn contains(&self, account_id: &AccountId) -> bool {
        self.account_ids.read().unwrap().contains(&account_id)
    }
}

#[derive(Debug, Clone)]
pub struct RegisterNotification<'c, C, AP: AccessPolicy> {
    enclave_input: input::RegisterNotification<AP>,
    enclave_context: &'c C,
}

impl<'c, C, AP: AccessPolicy> StateRuntimeEnclaveUseCase<'c, C> for RegisterNotification<'c, C, AP>
where
    C: ContextOps<S = StateType> + Clone,
{
    type EI = SodiumCiphertext;
    type EO = output::Empty;
    const ENCLAVE_USE_CASE_ID: u32 = REGISTER_NOTIFICATION_CMD;

    fn new(enclave_input: Self::EI, enclave_context: &'c C) -> anyhow::Result<Self> {
        let buf = enclave_context.decrypt(&enclave_input)?;
        let enclave_input = serde_json::from_slice(&buf[..])?;
        Ok(Self {
            enclave_input,
            enclave_context,
        })
    }

    fn eval_policy(&self) -> anyhow::Result<()> {
        self.enclave_input.access_policy().verify()
    }

    fn run(self) -> anyhow::Result<Self::EO> {
        let account_id = self.enclave_input.access_policy().into_account_id();
        self.enclave_context.set_notification(account_id);

        Ok(output::Empty::default())
    }
}

#[cfg(debug_assertions)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{
        PublicKey, Signature, SignatureError, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
    };
    use frame_common::crypto::Ed25519ChallengeResponse;
    use std::{string::String, vec::Vec};
    use test_utils::{run_tests, runner::*};

    pub(crate) fn run_tests() -> bool {
        run_tests!(test_notifier,)
    }

    fn test_notifier() {
        let notifier = Notifier::new();
        let access_policy = build_access_right().unwrap();
        let account_id = access_policy.verified_account_id().unwrap();

        assert!(
            !notifier.contains(&account_id),
            "notifier contains un-registered account_id: {:?}",
            account_id
        );
        assert!(
            notifier.register(account_id),
            "Failed to register account_id: {:?}",
            account_id
        );
        assert!(
            notifier.contains(&account_id),
            "notifier doesn't contain registered account_id: {:?}",
            account_id
        );
    }

    fn build_access_right() -> Result<Ed25519ChallengeResponse, SignatureError> {
        const SIG: [u8; SIGNATURE_LENGTH] = [
            21, 54, 136, 84, 150, 59, 196, 71, 164, 136, 222, 128, 100, 84, 208, 219, 84, 7, 61,
            11, 230, 220, 25, 138, 67, 247, 95, 97, 30, 76, 120, 160, 73, 48, 110, 43, 94, 79, 192,
            195, 82, 199, 73, 80, 48, 148, 233, 143, 87, 237, 159, 97, 252, 226, 68, 160, 137, 127,
            195, 116, 128, 181, 47, 2,
        ];

        const PUBKEY: [u8; PUBLIC_KEY_LENGTH] = [
            164, 189, 195, 42, 48, 163, 27, 74, 84, 147, 25, 254, 16, 14, 206, 134, 153, 148, 33,
            189, 55, 149, 7, 15, 11, 101, 106, 28, 48, 130, 133, 143,
        ];

        const CHALLENGE: [u8; 32] = [
            119, 177, 182, 220, 100, 44, 96, 179, 173, 47, 220, 49, 105, 204, 132, 230, 211, 24,
            166, 219, 82, 76, 27, 205, 211, 232, 142, 98, 66, 130, 150, 202,
        ];

        let sig = Signature::from_bytes(&SIG)?;
        let pubkey = PublicKey::from_bytes(&PUBKEY)?;

        Ok(Ed25519ChallengeResponse::new(sig, pubkey, CHALLENGE))
    }
}
