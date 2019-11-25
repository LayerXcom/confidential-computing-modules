use core::{fmt, default::Default, ptr};

pub const STATE_SIZE: usize = 8;
pub const PUBKEY_SIZE: usize = 64;
pub const ADDRESS_SIZE: usize = 20;
pub const RANDOMNESS_SIZE: usize = 32;
pub const SIG_SIZE: usize = 65;
pub const CIPHERTEXT_SIZE: usize = ADDRESS_SIZE + STATE_SIZE + RANDOMNESS_SIZE; // 60
pub const PLAINTEXT_SIZE: usize = CIPHERTEXT_SIZE; // 60
pub const DB_VALUE_SIZE: usize = STATE_SIZE + RANDOMNESS_SIZE;

pub type PubKey = [u8; PUBKEY_SIZE];
pub type Address = [u8; ADDRESS_SIZE];
pub type Randomness = [u8; RANDOMNESS_SIZE];
pub type Ciphertext = [u8; CIPHERTEXT_SIZE];
pub type Plaintext = [u8; PLAINTEXT_SIZE];
pub type Sig = [u8; SIG_SIZE];
pub type Msg = [u8; RANDOMNESS_SIZE];

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EnclaveReturn {
    /// Success, the function returned without any failure.
    Success,
}

impl Default for EnclaveReturn {
    fn default() -> EnclaveReturn { EnclaveReturn::Success }
}

impl fmt::Display for EnclaveReturn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::EnclaveReturn::*;
        let p = match *self {
            Success => "EnclaveReturn: Success",
        };
        write!(f, "{}", p)
    }
}

/// Returned from a contract deploy or state transition ecall.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TransitionResult {
    res: *const u8,
}

impl Default for TransitionResult {
    fn default() -> Self {
        TransitionResult {
            res: ptr::null(),
        }
    }
}

impl fmt::Debug for TransitionResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_trait_builder = f.debug_struct("TransitionResult");
        debug_trait_builder.field("res", &(self.res));
        debug_trait_builder.finish()
    }
}
