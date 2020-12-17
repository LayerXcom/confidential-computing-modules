

pub struct Quote {}

impl Quote {

}

pub fn get_quote() {
    let target_info = sgx_init_quote()?;
}