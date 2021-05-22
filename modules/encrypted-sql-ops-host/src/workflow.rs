//! Invokes ecall.
//!
//! FIXME: EcallController would be better name.

mod enclave_input;
mod enclave_output;
mod host_input;
mod host_output;

use frame_host::engine::*;

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
pub struct EncIntegerFromWorkflow;

impl HostEngine for EncIntegerFromWorkflow {
    type HI = host_input::RawInteger;
    type EI = enclave_input::RawInteger;
    type EO = enclave_output::EncIntegerWrapper;
    type HO = host_output::EncIntegerWrapper;
    const OUTPUT_MAX_LEN: usize = 64;
}
