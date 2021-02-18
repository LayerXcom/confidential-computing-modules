use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use frame_sodium::{SodiumCiphertext, SodiumPubKey};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Request {
    pub ciphertext: SodiumCiphertext,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
pub struct Response {
    pub enclave_encryption_key: SodiumPubKey,
}

/// Usage
/// ./enc <path/to/enclave_encryption_key file> <path/to/blob json file>
/// ex)
/// ```
/// ❯ ./target/debug/enc ./pubkey.json ./blob.100.json
/// ```
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("must have 3 args, got {}", args.len());
    }
    let pubkey_json = fs::read_to_string(args[1].as_str()).unwrap();
    let enclave_encryption_key: Response = serde_json::from_slice(pubkey_json.as_bytes()).unwrap();
    let blob_json = fs::read_to_string(args[2].as_str()).unwrap();

    let csprng = &mut OsRng;
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key.enclave_encryption_key,
        blob_json.as_bytes().to_vec(),
    )
    .unwrap();
    let req = json!(Request { ciphertext });
    save_encrypted_as_json(args[2].as_str(), &serde_json::to_vec(&req).unwrap());
}

fn save_encrypted_as_json(filename: &str, content: &[u8]) {
    let path = Path::new(filename);

    let filename = format!("encrypted_{}", path.file_name().unwrap().to_str().unwrap());
    let mut file = File::create(filename).unwrap();

    file.write_all(content).unwrap();
    file.flush().unwrap();
}
