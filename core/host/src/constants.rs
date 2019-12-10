pub const ENCLAVE_DIR: &'static str = ".anonify";
pub const ENCLAVE_TOKEN: &'static str = "enclave.token";
pub const ENCLAVE_FILE: &str = "../bin/enclave.signed.so";
pub const DEBUG: i32 = 1;

pub const DEV_HOSTNAME: &str = "api.trustedservices.intel.com";
pub const SIGRL_PATH: &str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_PATH: &str = "/sgx/dev/attestation/v3/report";
pub const HTTPS_PORT: u16 = 443;

pub const IAS_DEFAULT_RETRIES: u32 = 10;

pub const ANONYMOUS_ASSET_ABI_PATH: &str = "../../../build/AnonymousAsset.abi";
pub const ANONYMOUS_ASSET_BIN_PATH: &str = "../../../build/AnonymousAsset.bin";

pub const CONFIRMATIONS: usize = 0;
pub const POLL_INTERVAL_SECS: u64 = 10;
pub const DEPLOY_GAS: u64 = 3_000_000;
