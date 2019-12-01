#![no_std]
#![crate_type = "lib"]

#[macro_use]
extern crate sgx_tstd as std;

mod client;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
