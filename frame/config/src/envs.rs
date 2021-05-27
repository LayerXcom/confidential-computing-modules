#[cfg(feature = "sgx")]
use crate::localstd::vec::Vec;
use crate::localstd::{
    env,
    path::PathBuf,
    string::{String, ToString},
};
#[cfg(feature = "sgx")]
use crate::measurement::EnclaveMeasurement;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref REQUEST_RETRIES: usize = {
        env::var("REQUEST_RETRIES")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<usize>()
            .unwrap()
    };
    pub static ref RETRY_DELAY_MILLS: u64 = {
        env::var("RETRY_DELAY_MILLS")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<u64>()
            .unwrap()
    };
    pub static ref CMD_DEC_SECRET_DIR: String =
        env::var("CMD_DEC_SECRET_DIR").unwrap_or_else(|_| ".anonify/cmd-dec-secret".to_string());
    pub static ref PJ_ROOT_DIR: PathBuf = env::var("PJ_ROOT_DIR")
        .or_else(|_| env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| { panic!("PJ_ROOT_DIR is not set") });
    pub static ref BUILD_DIR: PathBuf = {
        let mut build_dir = PJ_ROOT_DIR.clone();
        build_dir.push("build");
        build_dir
    };
    pub static ref ANONIFY_ABI_PATH: PathBuf = {
        let abi_path_from_root = env::var("ANONIFY_ABI_PATH")
            .unwrap_or_else(|_| "contract-build/AnonifyWithEnclaveKey.abi".to_string());
        let mut abi_path = PJ_ROOT_DIR.clone();
        abi_path.push(abi_path_from_root);
        abi_path
    };
    pub static ref ANONIFY_BIN_PATH: PathBuf = {
        let bin_path_from_root = env::var("ANONIFY_BIN_PATH")
            .unwrap_or_else(|_| "contract-build/AnonifyWithEnclaveKey.bin".to_string());
        let mut bin_path = PJ_ROOT_DIR.clone();
        bin_path.push(bin_path_from_root);
        bin_path
    };
    pub static ref FACTORY_ABI_PATH: PathBuf = {
        let abi_path_from_root = env::var("FACTORY_ABI_PATH")
            .unwrap_or_else(|_| "contract-build/DeployAnonify.abi".to_string());
        let mut abi_path = PJ_ROOT_DIR.clone();
        abi_path.push(abi_path_from_root);
        abi_path
    };
    pub static ref FACTORY_BIN_PATH: PathBuf = {
        let bin_path_from_root = env::var("FACTORY_BIN_PATH")
            .unwrap_or_else(|_| "contract-build/DeployAnonify.bin".to_string());
        let mut bin_path = PJ_ROOT_DIR.clone();
        bin_path.push(bin_path_from_root);
        bin_path
    };
    pub static ref ANONIFY_PARAMS_DIR: PathBuf = {
        let mut measurement_file_path = PJ_ROOT_DIR.clone();
        measurement_file_path.push(".anonify");
        measurement_file_path
    };
}

#[cfg(feature = "sgx")]
lazy_static! {
    pub static ref ENCLAVE_SIGNED_SO: PathBuf = {
        let pkg_name = env::var("ENCLAVE_PKG_NAME").expect("ENCLAVE_PKG_NAME is not set");
        let mut measurement_file_path = ANONIFY_PARAMS_DIR.clone();
        measurement_file_path.push(format!("{}.signed.so", pkg_name));
        measurement_file_path
    };
    pub static ref ENCLAVE_MEASUREMENT: EnclaveMeasurement = {
        let pkg_name = env::var("ENCLAVE_PKG_NAME").expect("ENCLAVE_PKG_NAME is not set");
        let mut measurement_file_path = ANONIFY_PARAMS_DIR.clone();
        measurement_file_path.push(format!("{}_measurement.txt", pkg_name));

        let content = crate::localstd::untrusted::fs::read_to_string(&measurement_file_path)
            .expect("Cannot read measurement file");
        EnclaveMeasurement::new_from_dumpfile(content)
    };
    pub static ref ANONIFY_ENCLAVE_MEASUREMENT: EnclaveMeasurement = {
        let pkg_name = env::var("STATE_RUNTIME_ENCLAVE_PKG_NAME")
            .expect("STATE_RUNTIME_ENCLAVE_PKG_NAME is not set");
        let mut measurement_file_path = ANONIFY_PARAMS_DIR.clone();
        measurement_file_path.push(format!("{}_measurement.txt", pkg_name));

        let content = crate::localstd::untrusted::fs::read_to_string(&measurement_file_path)
            .expect("Cannot read measurement file");
        EnclaveMeasurement::new_from_dumpfile(content)
    };
    pub static ref KEY_VAULT_ENCLAVE_MEASUREMENT: EnclaveMeasurement = {
        let pkg_name =
            env::var("KEY_VAULT_ENCLAVE_PKG_NAME").expect("KEY_VAULT_ENCLAVE_PKG_NAME is not set");
        let mut measurement_file_path = ANONIFY_PARAMS_DIR.clone();
        measurement_file_path.push(format!("{}_measurement.txt", pkg_name));

        let content = crate::localstd::untrusted::fs::read_to_string(&measurement_file_path)
            .expect("Cannot read measurement file");
        EnclaveMeasurement::new_from_dumpfile(content)
    };
    pub static ref IAS_ROOT_CERT: Vec<u8> = {
        let ias_root_cert_path =
            env::var("IAS_ROOT_CERT_PATH").expect("IAS_ROOT_CERT_PATH is not set");
        let mut file_path = PJ_ROOT_DIR.clone();
        file_path.push(ias_root_cert_path);

        let ias_root_cert = crate::localstd::untrusted::fs::read(file_path).unwrap();
        let pem = pem::parse(ias_root_cert).expect("Cannot parse PEM File");
        pem.contents
    };
}
