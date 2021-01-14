#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

pub const START_SERVER_CMD: u32 = 1;
pub const STOP_SERVER_CMD: u32 = 2;
