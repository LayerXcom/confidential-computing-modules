use core::{fmt, default::Default, ptr};

pub const STATE_SIZE: usize = 8;
pub const PUBKEY_SIZE: usize = 32;
pub const ADDRESS_SIZE: usize = 20;
pub const RANDOMNESS_SIZE: usize = 32;
pub const SIG_SIZE: usize = 64;
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

#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum ResultStatus {
    /// Ok = Success = 1.
    Ok = 1,
    /// Failure = Error = 0.
    Failure = 0,
}

impl From<bool> for ResultStatus {
    fn from(i: bool) -> Self {
        if i {
            ResultStatus::Ok
        } else {
            ResultStatus::Failure
        }
    }
}

/// A wrapper to a raw mutable/immutable pointer.
/// The Edger8r will copy the data to the protected stack when you pass a pointer through the EDL.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawPointer {
    ptr: *const u8,
    _mut: bool
}

impl RawPointer {
    pub unsafe fn new<T>(_ref: &T) -> Self {
        RawPointer {
            ptr: _ref as *const T as *const u8,
            _mut: false,
        }
    }

    pub unsafe fn new_mut<T>(_ref: &mut T) -> Self {
        RawPointer {
            ptr: _ref as *mut T as *const u8,
            _mut: true,
        }
    }

    pub fn get_ptr<T>(&self) -> *const T {
        self.ptr as *const T
    }

    pub fn get_mut_ptr<T>(&self) -> Result<*mut T, &'static str> {
        if !self._mut {
            Err("This DoublePointer is not mutable")
        } else {
            Ok(self.ptr as *mut T)
        }
    }

    pub unsafe fn get_ref<T>(&self) -> &T {
        &*(self.ptr as *const T)
    }

    pub unsafe fn get_mut_ref<T>(&self) -> Result<&mut T, &'static str> {
        if !self._mut {
            Err("This DoublePointer is not mutable")
        } else {
            Ok(&mut *(self.ptr as *mut T) )
        }
    }
}
