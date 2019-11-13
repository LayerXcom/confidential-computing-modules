use std::{
    fs, path::{Path, PathBuf},
    io::{Read, Write, BufReader, BufWriter},
};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use crate::{
    constants::*,
    error::*,
};

pub struct EnclaveDir(PathBuf);

impl EnclaveDir {
    pub fn new() -> Self {
        let enclave_dir = dirs::home_dir()
            .expect("Cannot get enclave directory.")
            .join(ENCLAVE_DIR);

        if !enclave_dir.is_dir() {
            fs::create_dir_all(&enclave_dir)
                .expect("Cannot creat enclave directory.");
        }

        EnclaveDir(enclave_dir)
    }

    fn get_token_file_path(&self) -> PathBuf {
        self.0.join(ENCLAVE_TOKEN)
    }

    fn get_launch_token<P: AsRef<Path>>(path: P) -> Result<sgx_launch_token_t> {
        let mut buf = vec![];
        let f = fs::File::open(path)?;
        let mut reader = BufReader::new(f);
        reader.read_to_end(&mut buf)?;

        assert_eq!(buf.len(), 1024);
        let mut res = [0u8; 1024];
        res.copy_from_slice(&buf[..]);

        Ok(res)
    }

    fn save_launch_token<P: AsRef<Path>>(
        path: P,
        mut launch_token: sgx_launch_token_t
    ) -> Result<()> {
        let f = fs::File::create(path)?;
        let mut writer = BufWriter::new(f);
        writer.write_all(&launch_token[..])?;
        writer.flush()?;

        Ok(())
    }

    fn create_enclave(
        mut launch_token: sgx_launch_token_t,
        mut launch_token_updated: i32,
    ) -> SgxResult<SgxEnclave> {
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t {
                flags: 0,
                xfrm: 0,
            },
            misc_select: 0,
        };

        SgxEnclave::create(
            ENCLAVE_FILE,
            DEBUG,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )
    }
}

pub fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated = 0;

    let mut home_dir = PathBuf::new();
    let use_token = match dirs::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            home_dir = path;
            true
        },
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };


    let token_file: PathBuf = home_dir.join(ENCLAVE_TOKEN);;
    if use_token == true {
        match fs::File::open(&token_file) {
            Err(_) => {
                println!("[-] Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                println!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(1024) => {
                        println!("[+] Token file valid!");
                    },
                    _ => println!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }

    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t {
            flags: 0,
            xfrm: 0,
        },
        misc_select: 0,
    };
    let enclave = SgxEnclave::create(
        ENCLAVE_FILE,
        DEBUG,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    );

    if use_token == true && launch_token_updated != 0 {
        // reopen the file with write capablity
        match fs::File::create(&token_file) {
            Ok(mut f) => {
                match f.write_all(&launch_token) {
                    Ok(()) => println!("[+] Saved updated launch token!"),
                    Err(_) => println!("[-] Failed to save updated launch token!"),
                }
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            },
        }
    }

    enclave
}
