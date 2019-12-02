#![no_std]
#![crate_type = "lib"]

#[macro_use]
extern crate sgx_tstd as std;

mod client;
mod cache;
mod error;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
