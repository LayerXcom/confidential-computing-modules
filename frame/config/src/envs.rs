use crate::local_once_cell::sync::Lazy;
use crate::localstd::{
    env,
    ffi::OsStr,
    path::PathBuf,
    string::{String, ToString},
};

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
    let pkg_name = env::var("ENCLAVE_PKG_NAME").expect("ENCLAVE_PKG_NAME is not set");
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
