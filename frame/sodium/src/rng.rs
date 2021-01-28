#![cfg(feature = "sgx")]

use crate::localstd::{io, mem};
use rand_core::{CryptoRng, RngCore};
use sgx_trts::trts::rsgx_read_rand;
use sgx_types::*;

pub struct SgxRng;

impl SgxRng {
    /// Create a new `SgxRng`.
    pub fn new() -> io::Result<SgxRng> {
        Ok(SgxRng)
    }
}

impl RngCore for SgxRng {
    fn next_u32(&mut self) -> u32 {
        next_u32(&mut getrandom_fill_bytes)
    }
    fn next_u64(&mut self) -> u64 {
        next_u64(&mut getrandom_fill_bytes)
    }
    fn fill_bytes(&mut self, v: &mut [u8]) {
        getrandom_fill_bytes(v)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        try_getrandom_fill_bytes(dest)
    }
}

impl CryptoRng for SgxRng {}

fn next_u32(fill_buf: &mut dyn FnMut(&mut [u8])) -> u32 {
    let mut buf: [u8; 4] = [0; 4];
    fill_buf(&mut buf);
    unsafe { mem::transmute::<[u8; 4], u32>(buf) }
}

fn next_u64(fill_buf: &mut dyn FnMut(&mut [u8])) -> u64 {
    let mut buf: [u8; 8] = [0; 8];
    fill_buf(&mut buf);
    unsafe { mem::transmute::<[u8; 8], u64>(buf) }
}

fn getrandom(buf: &mut [u8]) -> SgxError {
    rsgx_read_rand(buf)
}

fn getrandom_fill_bytes(v: &mut [u8]) {
    getrandom(v).expect("unexpected getrandom error");
}

fn try_getrandom_fill_bytes(v: &mut [u8]) -> Result<(), rand_core::Error> {
    match getrandom(v) {
        Ok(_) => Ok(()),
        Err(ret) => Err(rand_core::Error::new(ret.from_key())),
    }
}

#[allow(dead_code)]
fn is_getrandom_available() -> bool {
    true
}
