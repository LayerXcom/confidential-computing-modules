//! Workflow def.
//!
//! FIXME: Workflow -> Controller

use super::host_types::{HostEncInteger, HostPlainInteger};
use frame_host::ecall_controller::EcallController;
use module_encrypted_sql_ops_ecall_types::enclave_types::{EnclaveEncInteger, EnclavePlainInteger};

/// Constructor of `ENCINTEGER` custom type.
///
/// # Important notice
///
/// Encrypted type constructors are virtually vulnerable in that:
///
/// - Users (who writes SQLs) can INSERT (or any other DML) secret data.
/// - SQL client and server takes the secret in plain text.
/// - Just after SQL server passes the secret to encrypted type constructors, the secret gets encrypted inside enclave.
///
/// # FIXME
///
/// [StealthDB](https://github.com/cryptograph/stealthdb), for example, has "Client Proxy" layer
/// to automatically encrypt secret data just after users submit an SQL.
/// Trustful transport layer via Remote-Attestation is used to exchange encryption key.
///
/// We should do the similar.
#[derive(Debug)]
pub struct EncIntegerFromController;

impl EcallController for EncIntegerFromController {
    type HI = HostPlainInteger;
    type EI = EnclavePlainInteger;
    type EO = EnclaveEncInteger;
    type HO = HostEncInteger;
    const EI_MAX_SIZE: usize = 64;

    fn translate_input(host_input: Self::HI) -> anyhow::Result<Self::EI> {
        Ok(EnclavePlainInteger::from(host_input.to_i32()))
    }

    fn translate_output(enclave_output: Self::EO) -> anyhow::Result<Self::HO> {
        Ok(HostEncInteger::from(enclave_output))
    }
}
