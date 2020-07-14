use std::{
    path::Path,
    sync::Arc,
    boxed::Box,
};
use sgx_types::sgx_enclave_id_t;
use anonify_types::{RawJoinGroupTx, RawHandshakeTx};
use anonify_common::{
    crypto::{AccessRight, Ciphertext},
    traits::{State, CallNameConverter},
    state_types::UpdatedState,
    plugin_types::*,
};
use web3::types::Address as EthAddress;
use crate::{
    error::Result,
    eventdb::{BlockNumDB, InnerEnclaveLog},
    traits::*,
    utils::*,
};
use super::primitives::{Web3Http, Web3Contract};

/// Components needed to deploy a contract
#[derive(Debug)]
pub struct EthDeployer {
    enclave_id: sgx_enclave_id_t,
    web3_conn: Web3Http,
    address: Option<EthAddress>, // contract address
}

impl Deployer for EthDeployer {
    fn new(enclave_id: sgx_enclave_id_t, node_url: &str) -> Result<Self> {
        let web3_conn = Web3Http::new(node_url)?;

        Ok(EthDeployer {
            enclave_id,
            web3_conn,
            address: None,
        })
    }

    fn get_account(&self, index: usize) -> Result<SignerAddress> {
        Ok(SignerAddress::EthAddress(
            self.web3_conn.get_account(index)?
        ))
    }

    fn deploy<F>(
        &mut self,
        deploy_user: &SignerAddress,
        reg_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<RawJoinGroupTx>,
    {
        let join_group_tx: BoxedJoinGroupTx = reg_fn(self.enclave_id)?.into();

        let contract_addr = match deploy_user {
            SignerAddress::EthAddress(address) => {
                self.web3_conn.deploy(
                    &address,
                    &join_group_tx.report,
                    &join_group_tx.report_sig,
                    &join_group_tx.handshake,
                )?
            }
        };
        self.address = Some(contract_addr);

        Ok(hex::encode(contract_addr.as_bytes()))
    }

    // TODO: generalize, remove abi.
    fn get_contract<P: AsRef<Path>>(self, abi_path: P) -> Result<ContractKind> {
        let addr = self.address.expect("The contract hasn't be deployed yet.").to_string();
        let contract_info = ContractInfo::new(abi_path, &addr);
        Ok(ContractKind::Web3Contract(
            Web3Contract::new(self.web3_conn, contract_info)?
        ))
    }

    fn get_enclave_id(&self) -> sgx_enclave_id_t {
        self.enclave_id
    }

    fn get_node_url(&self) -> &str {
        &self.web3_conn.get_eth_url()
    }

    fn register_notification<F>(
        &self,
        access_right: AccessRight,
        reg_notify_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(sgx_enclave_id_t, AccessRight) -> Result<()>,
    {
        reg_notify_fn(self.enclave_id, access_right)
    }
}

/// Components needed to send a transaction
#[derive(Debug)]
pub struct EthSender {
    enclave_id: sgx_enclave_id_t,
    contract: Web3Contract,
}

impl Sender for EthSender {
    fn new<P: AsRef<Path>>(
        enclave_id: sgx_enclave_id_t,
        node_url: &str,
        contract_info: ContractInfo<'_, P>,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info)?;

        Ok(EthSender { enclave_id, contract })
    }

    fn from_contract(
        enclave_id: sgx_enclave_id_t,
        contract: ContractKind,
    ) -> Self {
        match contract {
            ContractKind::Web3Contract(contract) => {
                EthSender {
                    enclave_id,
                    contract,
                }
            }
        }
    }

    fn get_account(&self, index: usize) -> Result<SignerAddress> {
        Ok(SignerAddress::EthAddress(
            self.contract.get_account(index)?
        ))
    }

    fn join_group<F>(
        &self,
        signer: SignerAddress,
        gas: u64,
        reg_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<RawJoinGroupTx>,
    {
        let join_group_tx: BoxedJoinGroupTx = reg_fn(self.enclave_id)?.into();
        let receipt = match signer {
            SignerAddress::EthAddress(addr) => {
                self.contract.join_group(
                    addr,
                    &join_group_tx.report,
                    &join_group_tx.report_sig,
                    &join_group_tx.handshake,
                    gas
                )?
            }
        };

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn send_instruction<ST, F, C>(
        &self,
        access_right: AccessRight,
        signer: SignerAddress,
        state_info: StateInfo<'_, ST, C>,
        gas: u64,
        enc_ins_fn: F,
        ciphertext_len: usize,
    ) -> Result<String>
    where
        ST: State,
        C: CallNameConverter,
        F: FnOnce(sgx_enclave_id_t, AccessRight, StateInfo<'_, ST, C>) -> Result<output::Instruction>,
    {
        // ecall of encrypt instruction
        let instruction_tx: output::Instruction = enc_ins_fn(self.enclave_id, access_right, state_info)?;

        let receipt = match signer {
            SignerAddress::EthAddress(addr) => {
                self.contract.send_instruction(
                    addr,
                    instruction_tx.encode_ciphertext(),
                    &instruction_tx.encode_enclave_sig(),
                    &instruction_tx.msg_as_bytes(),
                    gas,
                )?
            }
        };

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn handshake<F>(
        &self,
        signer: SignerAddress,
        gas: u64,
        handshake_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<RawHandshakeTx>
    {
        let handshake_tx: BoxedHandshakeTx = handshake_fn(self.enclave_id)?.into();
        let receipt = match signer {
            SignerAddress::EthAddress(addr) => {
                self.contract.handshake(
                    addr,
                    &handshake_tx.handshake,
                    gas
                )?
            }
        };

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}

/// Components needed to watch events
pub struct EventWatcher<DB: BlockNumDB> {
    contract: Web3Contract,
    event_db: Arc<DB>,
}

impl<DB: BlockNumDB> Watcher for EventWatcher<DB> {
    type WatcherDB = DB;

    fn new<P: AsRef<Path>>(
        node_url: &str,
        contract_info: ContractInfo<'_, P>,
        event_db: Arc<DB>,
    ) -> Result<Self> {
        let web3_http = Web3Http::new(node_url)?;
        let contract = Web3Contract::new(web3_http, contract_info)?;

        Ok(EventWatcher { contract, event_db })
    }

    fn block_on_event<F, S>(
        &self,
        eid: sgx_enclave_id_t,
        insert_fn: F,
    ) -> Result<Option<Vec<UpdatedState<S>>>>
    where
        F: FnOnce(sgx_enclave_id_t, &InnerEnclaveLog, usize) -> Result<Option<Vec<UpdatedState<S>>>>,
        S: State,
    {
        let enclave_updated_state = self.contract
            .get_event(self.event_db.clone(), self.contract.address())?
            .into_enclave_log()?
            .insert_enclave(eid, insert_fn)?
            .set_to_db(self.contract.address());

        Ok(enclave_updated_state.updated_states())
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BoxedJoinGroupTx {
    pub report: Box<[u8]>,
    pub report_sig: Box<[u8]>,
    pub handshake: Box<[u8]>,
}

impl From<RawJoinGroupTx> for BoxedJoinGroupTx {
    fn from(raw_reg_tx: RawJoinGroupTx) -> Self {
        let mut res_tx = BoxedJoinGroupTx::default();

        let box_report = raw_reg_tx.report as *mut Box<[u8]>;
        let report = unsafe { Box::from_raw(box_report) };
        let box_report_sig = raw_reg_tx.report_sig as *mut Box<[u8]>;
        let report_sig = unsafe { Box::from_raw(box_report_sig) };
        let box_handshake = raw_reg_tx.handshake as *mut Box<[u8]>;
        let handshake = unsafe { Box::from_raw(box_handshake) };

        res_tx.report = *report;
        res_tx.report_sig = *report_sig;
        res_tx.handshake = *handshake;

        res_tx
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BoxedHandshakeTx {
    pub handshake: Box<[u8]>,
}

impl From<RawHandshakeTx> for BoxedHandshakeTx {
    fn from(raw_handshake_tx: RawHandshakeTx) -> Self {
        let mut res_tx = BoxedHandshakeTx::default();
        let box_handshake = raw_handshake_tx.handshake as *mut Box<[u8]>;
        let handshake = unsafe { Box::from_raw(box_handshake) };
        res_tx.handshake = *handshake;

        res_tx
    }
}
