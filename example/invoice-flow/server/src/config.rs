use anonify_wallet::{DirOperations, KeystoreDirectory, WalletDirectory};
use ed25519_dalek::Keypair;
use failure::Error;
use std::env;
use std::path::PathBuf;

const KEYSTORE_DIRECTORY_NAME: &'static str = "fixture";

pub fn get_keypair_from_keystore(password: &[u8], keyfile_index: usize) -> Result<Keypair, Error> {
    let root_dir = env::current_dir()?
        .parent()
        .unwrap()
        .join(KEYSTORE_DIRECTORY_NAME);
    println!("current dir: {:?}", root_dir);

    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;
    let keyfile = &keystore_dir.load_all()?[keyfile_index];
    let keypair = keyfile.get_key_pair(password)?;

    Ok(keypair)
}

fn wallet_keystore_dirs(root_dir: &PathBuf) -> Result<(WalletDirectory, KeystoreDirectory), Error> {
    // configure wallet directory
    let wallet_dir = WalletDirectory::create(&root_dir)?;

    // configure ketstore directory
    let keystore_dir_path = wallet_dir.get_default_keystore_dir();
    let keystore_dir = KeystoreDirectory::create(keystore_dir_path)?;

    Ok((wallet_dir, keystore_dir))
}
