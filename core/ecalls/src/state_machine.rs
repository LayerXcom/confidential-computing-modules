use std::collections::HashSet;
use std::vec::Vec;
use std::fmt::Debug;
use anyhow::Result;
use anonify_common::context_switch::*;

pub enum ExecPhase<A: AccessControl, E: Execution> {
    AccessControl(EnclaveStateMachine<AccessControlImpl<A, E>>),
    // TODO:
    // Decryption(),
    // Execution(),
    // Encryption(),
    // Signing(),
}

impl<A: AccessControl, E: Execution> ExecPhase<A, E> {
    pub fn new(input: EcallInputType<A, E>) -> Self {
        unimplemented!();
    }

    pub fn step(self) -> Result<Self> {
        unimplemented!();
        // match self {
        //     ExecPhase::AccessControl(s) if !s.skip_phases.containes(1) => {
        //         if !s.state.access_control.is_allowed() {
        //             return Err();
        //         }

        //         Ok(self.execution)
        //     },
        // }
    }

    pub fn skip(self) -> Self {
        unimplemented!();
    }

    pub fn finalize(self) -> Output {
        unimplemented!();
    }
}

pub struct EnclaveStateMachine<S> {
    state: S,
    signature: Option<Signature>,
    skip_phases: HashSet<u8>,
    // enc_key
    // sign_key,
    // kvs,
}

pub struct Plaintext(Vec<u8>);

pub struct Ciphertext(Vec<u8>);

pub struct Signature(Vec<u8>);

pub struct Output(Vec<u8>);

pub struct AccessControlImpl<A: AccessControl, E: Execution> {
    access_control: A,
    execution: E,
}

pub struct ExecutionImpl<E: Execution> {
    execution: E,
}
