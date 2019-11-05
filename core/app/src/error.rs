use sgx_types::sgx_status_t;

#[derive(Fail, Debug)]
#[fail(display = "SGX Ecall Failed function: {}, status: {}", function, status)]
pub struct SgxError {
    pub status: sgx_status_t,
    pub function: &'static str,
}

