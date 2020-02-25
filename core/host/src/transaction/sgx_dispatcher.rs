use std::{
    path::Path,
    sync::Arc,
    convert::{TryInto, TryFrom},
    fmt::Debug,
};
use sgx_types::sgx_enclave_id_t;
use crate::bridges::ecalls::{
    register as reg_fn,
    state_transition as st_fn,
    insert_logs as insert_fn,
    get_state_from_enclave,
};
use crate::error::{HostErrorKind, Result};
use super::{
    dispatcher::{
        SignerAddress,
        ContractKind,
        traits::*,
    },
    utils::{ContractInfo, StateInfo},
    eventdb::BlockNumDB,
};
use anonify_common::AccessRight;
use anonify_runtime::State;
use anonify_types::{RawRegisterTx, RawStateTransTx};

#[derive(Debug)]
pub struct SgxDispatcher<D: Deployer, S: Sender, W: Watcher<WatcherDB=DB>, DB: BlockNumDB> {
    deployer: D,
    sender: Option<S>,
    watcher: Option<W>,
    event_db: Arc<DB>,
}

impl<D, S, W, DB> SgxDispatcher<D, S, W, DB>
where
    D: Deployer,
    S: Sender,
    W: Watcher<WatcherDB=DB>,
    DB: BlockNumDB,
{
    pub fn new_with_deployer(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        event_db: Arc<DB>,
    ) -> Result<Self> {
        let deployer = D::new(enclave_id, node_url)?;

        Ok(SgxDispatcher {
            deployer,
            event_db,
            sender: None,
            watcher: None,
        })
    }

    pub fn set_contract_addr<P>(
        &mut self,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<()>
    where
        P: AsRef<Path> + Copy
    {
        let enclave_id = self.deployer.get_enclave_id();
        let node_url = self.deployer.get_node_url();
        let sender = S::new(enclave_id, node_url, contract_info)?;
        let watcher = W::new(node_url, contract_info, self.event_db.clone())?;

        self.sender = Some(sender);
        self.watcher = Some(watcher);

        Ok(())
    }

    pub fn deploy(
        &mut self,
        deploy_user: &SignerAddress,
        access_right: &AccessRight,
    ) -> Result<String> {
        self.deployer.deploy(deploy_user, access_right, reg_fn)
    }

    pub fn get_account(&self, index: usize) -> Result<SignerAddress> {
        self.deployer.get_account(index)
    }

    pub fn block_on_event<P: AsRef<Path> + Copy>(
        &mut self,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<()> {
        // If contract address is not set, set new contract address and abi path to generate watcher instance.
        // if let None = self.watcher.as_mut() {
            self.set_contract_addr(contract_info)?;
        // }

        let eid = self.deployer.get_enclave_id();
        self.watcher.as_ref()
            .ok_or(HostErrorKind::Msg("Contract address have not been set."))?
            .block_on_event(eid, insert_fn)
    }

    pub fn register<P: AsRef<Path> + Copy>(
        &mut self,
        signer: SignerAddress,
        gas: u64,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<String> {
        self.set_contract_addr(contract_info)?;

        self.sender.as_ref()
            .ok_or(HostErrorKind::Msg("Contract address have not been set collectly."))?
            .register(signer, gas, reg_fn)
    }

    pub fn state_transition<ST, P>(
        &mut self,
        access_right: AccessRight,
        signer: SignerAddress,
        state_info: StateInfo<'_, ST>,
        contract_info: ContractInfo<'_, P>,
        gas: u64,
    ) -> Result<String>
    where
        ST: State,
        P: AsRef<Path> + Copy,
    {
        // If contract address is not set, set new contract address and abi path to generate sender instance.
        // if let None = self.sender.as_mut() {
            self.set_contract_addr(contract_info)?;
        // }

        self.sender.as_ref()
            .ok_or(HostErrorKind::Msg("Contract address have not been set collectly."))?
            .state_transition(access_right, signer, state_info, gas, st_fn)
    }
}

pub fn get_state_sgx<S>(
    access_right: &AccessRight,
    enclave_id: sgx_enclave_id_t,
    mem_name: &str,
) -> Result<S>
where
    S: State + TryFrom<Vec<u8>>,
    <S as TryFrom<Vec<u8>>>::Error: Debug,
{
    let state = get_state_from_enclave(
        enclave_id,
        &access_right.sig(),
        &access_right.pubkey(),
        &access_right.challenge(),
        mem_name,
    )?
    .try_into()
    .expect("Failed to convert into State trait.");

    Ok(state)
}
