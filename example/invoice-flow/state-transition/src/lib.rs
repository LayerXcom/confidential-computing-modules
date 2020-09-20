#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as localstd;
#[cfg(feature = "std")]
use std as localstd;

use crate::localstd::vec::Vec;
use frame_runtime::prelude::*;

pub const MAX_MEM_SIZE: usize = 5000;
pub const CIPHERTEXT_SIZE: usize = MAX_MEM_SIZE + 30;

impl_memory! {
    (0, "Invoice", Bytes)
}

impl_runtime! {
    #[fn_id=0]
    pub fn send_invoice(
        self,
        _sender: AccountId,
        recipient: AccountId,
        invoice: Bytes
    ) {
        let invoice_update = update!(recipient, "Invoice", invoice);
        insert![invoice_update]
    }
}
