#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "backup-enable")]
mod backup;
mod commands;
pub mod context;
mod enclave_key;
mod error;
mod group_key;
mod handshake;
mod join_group;
mod kvs;
mod notify;

pub mod use_case {
    #[cfg(feature = "backup-enable")]
    pub use crate::backup::{
        EnclaveKeyBackupper, EnclaveKeyRecoverer, PathSecretsBackupper, PathSecretsRecoverer,
    };
    pub use crate::commands::{
        enclave_key::{CommandByEnclaveKeyReceiver, CommandByEnclaveKeySender},
        treekem::{CommandByTreeKemReceiver, CommandByTreeKemSender},
    };
    pub use crate::context::{GetState, GetUserCounter, ReportRegistration};
    pub use crate::enclave_key::EncryptionKeyGetter;
    pub use crate::handshake::{HandshakeReceiver, HandshakeSender};
    pub use crate::join_group::{
        enclave_key::JoinGroupWithEnclaveKey, treekem::JoinGroupWithTreeKem,
    };
    pub use crate::notify::RegisterNotification;
}

#[cfg(debug_assertions)]
pub mod tests {
    use super::*;
    use std::prelude::v1::*;
    use test_utils::check_all_passed;

    pub fn run_tests() -> bool {
        check_all_passed!(notify::tests::run_tests(),)
    }
}
