use anonify_io_types::*;
use frame_common::{crypto::AccountId, state_types::StateType, AccessPolicy};
use frame_enclave::EnclaveEngine;
use frame_runtime::traits::*;
use std::marker::PhantomData;
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
pub struct RegisterNotification<AP: AccessPolicy> {
    phantom: PhantomData<AP>,
}

impl<AP: AccessPolicy> EnclaveEngine for RegisterNotification<AP> {
    type EI = input::RegisterNotification<AP>;
    type EO = output::Empty;

    fn eval_policy(ecall_input: &Self::EI) -> anyhow::Result<()> {
        ecall_input.access_policy().verify()
    }

    fn handle<R, C>(
        ecall_input: Self::EI,
        enclave_context: &C,
        _max_mem_size: usize,
    ) -> anyhow::Result<Self::EO>
    where
        R: RuntimeExecutor<C, S = StateType>,
        C: ContextOps<S = StateType> + Clone,
    {
        let account_id = ecall_input.access_policy().into_account_id();
        enclave_context.set_notification(account_id);

        Ok(output::Empty::default())
    }
}
