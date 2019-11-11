pub const ENCLAVE_TOKEN: &str = "../bin/enclave.token";
pub const ENCLAVE_FILE: &str = "../bin/enclave.signed.so";
pub const DEBUG: i32 = 1;

pub const SPID: &str = "2C149BFC94A61D306A96211AED155BE9";
pub const IAS_URL: &str = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report";
pub const SIGRL_SUFFIX : &str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX	: &str = "/sgx/dev/attestation/v3/report";

pub const IAS_DEFAULT_RETRIES: u32 = 10;

pub const ANONYMOUS_ASSET_ABI_PATH: &str = "../../../build/AnonymousAsset.abi";
pub const ANONYMOUS_ASSET_BIN_PATH: &str = "../../../build/AnonymousAsset.bin";

pub const CONFIRMATIONS: usize = 0;
pub const POLL_INTERVAL_SECS: u64 = 10;
pub const DEPLOY_GAS: u64 = 3_000_00;
