use std::{
    path::Path,
    sync::Arc,
    boxed::Box,
};
use sgx_types::sgx_enclave_id_t;
use anonify_types::{RawRegisterTx, RawInstructionTx, RawHandshakeTx};
use anonify_common::AccessRight;
use anonify_runtime::traits::State;
use anonify_app_preluder::Ciphertext;
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
        F: FnOnce(sgx_enclave_id_t) -> Result<RawRegisterTx>,
    {
        let register_tx: BoxedRegisterTx = reg_fn(self.enclave_id)?.into();

        let contract_addr = match deploy_user {
            SignerAddress::EthAddress(address) => {
                self.web3_conn.deploy(
                    &address,
                    &register_tx.report,
                    &register_tx.report_sig,
                    &register_tx.handshake,
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

    fn register<F>(
        &self,
        signer: SignerAddress,
        gas: u64,
        reg_fn: F,
    ) -> Result<String>
    where
        F: FnOnce(sgx_enclave_id_t) -> Result<RawRegisterTx>,
    {
        let register_tx: BoxedRegisterTx = reg_fn(self.enclave_id)?.into();
        let receipt = match signer {
            SignerAddress::EthAddress(addr) => {
                self.contract.register(
                    addr,
                    &register_tx.report,
                    &register_tx.report_sig,
                    &register_tx.handshake,
                    gas
                )?
            }
        };

        Ok(hex::encode(receipt.as_bytes()))
    }

    fn send_instruction<ST, F>(
        &self,
        access_right: AccessRight,
        signer: SignerAddress,
        state_info: StateInfo<'_, ST>,
        gas: u64,
        enc_ins_fn: F,
    ) -> Result<String>
    where
        ST: State,
        F: FnOnce(sgx_enclave_id_t, AccessRight, StateInfo<'_, ST>) -> Result<RawInstructionTx>,
    {
        // ecall of encrypt instruction
        let mut instruction_tx: BoxedInstructionTx = enc_ins_fn(self.enclave_id, access_right, state_info)?.into();
        let ciphertext = instruction_tx.get_ciphertext();

        let receipt = match signer {
            SignerAddress::EthAddress(addr) => {
                self.contract.send_instruction(
                    addr,
                    instruction_tx.state_id,
                    ciphertext,
                    &instruction_tx.enclave_sig,
                    &instruction_tx.msg,
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

    fn block_on_event<F>(
        &self,
        eid: sgx_enclave_id_t,
        insert_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(sgx_enclave_id_t, &InnerEnclaveLog) -> Result<()>,
    {
        self.contract
            .get_event(self.event_db.clone(), self.contract.address())?
            .into_enclave_log()?
            .insert_enclave(eid, insert_fn)?
            .set_to_db(self.contract.address());

        Ok(())
    }

    fn get_contract(self) -> ContractKind {
        ContractKind::Web3Contract(self.contract)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BoxedRegisterTx {
    pub report: Box<[u8]>,
    pub report_sig: Box<[u8]>,
    pub handshake: Box<[u8]>,
}

impl From<RawRegisterTx> for BoxedRegisterTx {
    fn from(raw_reg_tx: RawRegisterTx) -> Self {
        let mut res_tx = BoxedRegisterTx::default();

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
pub(crate) struct BoxedInstructionTx {
    pub state_id: u64,
    pub ciphertext: Box<[u8]>,
    pub enclave_sig: Box<[u8]>,
    pub msg: Box<[u8]>,
}

impl BoxedInstructionTx {
    pub fn get_ciphertext(&mut self) -> Ciphertext {
        Ciphertext::from_bytes(&mut self.ciphertext)
    }
}

impl From<RawInstructionTx> for BoxedInstructionTx {
    fn from(raw_instruction_tx: RawInstructionTx) -> Self {
        let mut res_tx = BoxedInstructionTx::default();

        let box_ciphertext = raw_instruction_tx.ciphertext as *mut Box<[u8]>;
        let ciphertext = unsafe { Box::from_raw(box_ciphertext) };
        let box_enclave_sig = raw_instruction_tx.enclave_sig as *mut Box<[u8]>;
        let enclave_sig = unsafe { Box::from_raw(box_enclave_sig) };
        let box_msg = raw_instruction_tx.msg as *mut Box<[u8]>;
        let msg = unsafe { Box::from_raw(box_msg) };

        res_tx.state_id = raw_instruction_tx.state_id;
        res_tx.ciphertext = *ciphertext;
        res_tx.enclave_sig = *enclave_sig;
        res_tx.msg = *msg;

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
