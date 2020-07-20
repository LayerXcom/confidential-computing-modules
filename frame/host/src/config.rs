pub const ENCLAVE_DIR: &'static str = ".anonify";
pub const ENCLAVE_TOKEN: &'static str = "enclave.token";
pub const ENCLAVE_FILE: &'static str = "enclave.signed.so";


#[derive(Debug, Clone)]
pub struct Config {
    tee_kind: TEEKind,
    output_kind: OutputKind,
}

impl Config {
    pub fn new(tee_kind: TEEKind, output_kind: OutputKind) -> Self {
        Config { tee_kind, output_kind }
    }
}

#[derive(Debug, Clone)]
pub enum TEEKind {
    SGX,
}

#[derive(Debug, Clone)]
pub enum OutputKind {
    Eth,
}
