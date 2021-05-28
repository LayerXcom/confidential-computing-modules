//! Encryption / Decryption logic for AvgState

use crate::{error::Result, plain_types::PlainAvgState};
use module_encrypted_sql_ops_ecall_types::enc_type::enc_aggregate_state::EncAvgState;

pub(crate) trait EncAvgStateDecrypt {
    fn decrypt(self) -> Result<PlainAvgState>;
}

pub(crate) trait EncAvgStateEncrypt {
    fn encrypt(self) -> EncAvgState;
}

impl EncAvgStateDecrypt for EncAvgState {
    fn decrypt(self) -> Result<PlainAvgState> {
        todo!()
    }
}

impl EncAvgStateEncrypt for PlainAvgState {
    fn encrypt(self) -> EncAvgState {
        todo!()
    }
}
