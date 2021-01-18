use crate::local_once_cell::sync::Lazy;
use crate::localstd::{
    env,
    ffi::OsStr,
    path::PathBuf,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "sgx")]
use crate::measurement::EnclaveMeasurement;

pub static REQUEST_RETRIES: Lazy<usize> = Lazy::new(|| {
    env::var("REQUEST_RETRIES")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<usize>()
        .unwrap()
});

pub static RETRY_DELAY_MILLS: Lazy<u64> = Lazy::new(|| {
    env::var("RETRY_DELAY_MILLS")
        .unwrap_or_else(|_| "100".to_string())
        .parse::<u64>()
        .unwrap()
});

pub static PATH_SECRETS_DIR: Lazy<String> =
    Lazy::new(|| env::var("PATH_SECRETS_DIR").unwrap_or(".anonify/pathsecrets".to_string()));

pub static PJ_ROOT_DIR: Lazy<PathBuf> = Lazy::new(|| {
    let mut current_dir = env::current_dir().unwrap();
    loop {
        if current_dir.file_name() == Some(OsStr::new("anonify")) {
            break;
        }
        if !current_dir.pop() {
            break;
        }
    }

    current_dir
});

#[cfg(feature = "sgx")]
pub static ENCLAVE_SIGNED_SO: Lazy<PathBuf> = Lazy::new(|| {
    let pkg_name = env::var("MY_ENCLAVE_PKG_NAME").expect("MY_ENCLAVE_PKG_NAME is not set");
    let mut measurement_file_path = PJ_ROOT_DIR.clone();

    let measurement_file = match env::var("BACKUP") {
        Ok(backup) if backup == "disable" => {
            format!(".anonify/{}.backup_disabled.signed.so", pkg_name)
        }
        _ => format!(".anonify/{}.signed.so", pkg_name),
    };
    measurement_file_path.push(measurement_file);
    measurement_file_path
});

#[cfg(feature = "sgx")]
pub static MY_ENCLAVE_MEASUREMENT: Lazy<EnclaveMeasurement> = Lazy::new(|| {
    let pkg_name = env::var("MY_ENCLAVE_PKG_NAME").expect("MY_ENCLAVE_PKG_NAME is not set");
    let mut measurement_file_path = PJ_ROOT_DIR.clone();

    let measurement_file = match env::var("BACKUP") {
        Ok(backup) if backup == "disable" => {
            format!(".anonify/{}_backup_disabled_measurement.txt", pkg_name)
        }
        _ => format!(".anonify/{}_measurement.txt", pkg_name),
    };

    measurement_file_path.push(measurement_file);
    let content = crate::localstd::untrusted::fs::read_to_string(&measurement_file_path)
        .expect("Cannot read measurement file");
    EnclaveMeasurement::new_from_dumpfile(content)
});

#[cfg(feature = "sgx")]
pub static CONNECTED_ENCLAVE_MEASUREMENT: Lazy<EnclaveMeasurement> = Lazy::new(|| {
    let pkg_name =
        env::var("CONNECTED_ENCLAVE_PKG_NAME").expect("CONNECTED_ENCLAVE_PKG_NAME is not set");
    let mut measurement_file_path = PJ_ROOT_DIR.clone();

    let measurement_file = match env::var("BACKUP") {
        Ok(backup) if backup == "disable" => {
            format!(".anonify/{}_backup_disabled_measurement.txt", pkg_name)
        }
        _ => format!(".anonify/{}_measurement.txt", pkg_name),
    };

    measurement_file_path.push(measurement_file);
    let content = crate::localstd::untrusted::fs::read_to_string(&measurement_file_path)
        .expect("Cannot read measurement file");
    EnclaveMeasurement::new_from_dumpfile(content)
});

#[cfg(feature = "sgx")]
pub static IAS_ROOT_CERT: Lazy<Vec<u8>> = Lazy::new(|| {
    let ias_root_cert_path = env::var("IAS_ROOT_CERT_PATH").expect("IAS_ROOT_CERT_PATH is not set");
    let mut file_path = PJ_ROOT_DIR.clone();
    file_path.push(ias_root_cert_path);

    let ias_root_cert = crate::localstd::untrusted::fs::read(file_path).unwrap();
    let pem = pem::parse(ias_root_cert).expect("Cannot parse PEM File");
    pem.contents
});
