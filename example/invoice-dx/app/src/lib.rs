#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;

#[cfg(feature = "std")]
use std as localstd;

#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

use anonify_runtime::{
    prelude::*,
    state_type::*,
};
use crate::localstd::{
    string::String,
    vec::Vec,
};
use anonify_common::UserAddress;
use codec::{Encode, Decode};

pub const MAX_MEM_SIZE: usize = 2000;
pub const CIPHERTEXT_SIZE: usize = MAX_MEM_SIZE + 30;

impl_memory! {
    (0, "Invoice", Bytes)
}

impl_runtime! {
    #[fn_id=0]
    pub fn send_invoice(
        self,
        _sender: UserAddress,
        recipient: UserAddress,
        invoice: Bytes
    ) {
        let invoice_update = update!(recipient, "Invoice", invoice);
        insert![invoice_update]
    }
}
