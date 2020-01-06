use std::path::PathBuf;
use rand::Rng;
use anonify_wallet::{WalletDirectory, KeystoreDirectory, KeyFile, DirOperations};
use anonify_common::UserAddress;
use anonymous_asset::api;
use bip39::{Mnemonic, Language, MnemonicType, Seed};
use reqwest::Client;
use ed25519_dalek::Keypair;
use crate::{
    term::Term,
    error::Result,
    config::{VERSION, ITERS},
};

pub(crate) fn deploy<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    total_supply: u64,
    rng: &mut R
) -> Result<()> {
    let password = prompt_password(term)?;

    let client = Client::new();
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;

    let req = api::deploy::post::Request::new(&keypair, total_supply, rng);

    let res = client
        .post(&format!("{}/deploy", &anonify_url))
        .json(&req)
        .send()?
        .text()?;

    println!("Deployed Contract address: {}", res);
    Ok(())
}

pub(crate) fn send<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    target: UserAddress,
    amount: u64,
    contract_addr: String,
    rng: &mut R
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;

    let req = api::send::post::Request::new(&keypair, amount, target, contract_addr, rng);
    println!("Reqest json: {:?}", &req);
    let res = Client::new()
        .post(&format!("{}/send", &anonify_url))
        .json(&req)
        .send()?
        .text()?;

    println!("Transaction Receipt: {}", res);
    Ok(())
}

pub(crate) fn get_state<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    contract_addr: String,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;

    let req = api::state::get::Request::new(&keypair, contract_addr, rng);
    println!("Reqest json: {:?}", &req);
    let res = Client::new()
        .get(&format!("{}/state", &anonify_url))
        .json(&req)
        .send()?
        .text()?;

    println!("Current State: {}", res);
    Ok(())
}

/// Create a new wallet
pub(crate) fn new_wallet<R: Rng>(term: &mut Term, root_dir: PathBuf, rng: &mut R) -> Result<()> {
    // 1. configure wallet directory
    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // 2. configure user-defined passoword
    term.info("Set a wallet password. This is for local use only. It allows you to protect your cached private key and prevents the creation of non-desired transactions.\n")?;
    let password = term.new_password("wallet password", "confirm wallet password", "password mismatch")?;

    // 3. generate the mnemonics
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = mnemonic.phrase();
    term.info("Please, note carefully the following mnemonic words. They will be needed to recover your wallet.\n")?;
    term.error(&format!("{}\n", phrase))?;

    // 4. enter new account name
    term.info("Enter a new account name.\n")?;
    let account_name = term.account_name("new account name")?;

    // 5. create keyfile
    let seed = Seed::new(&mnemonic, "");
    let seed_vec = seed.as_bytes();
    let mut keyfile = KeyFile::new_from_seed(
        account_name.as_str(),
        VERSION,
        &password,
        ITERS,
        &seed_vec,
        rng
    )?;

    // 6. store a keyfile
    keystore_dir.insert(&mut keyfile, rng)?;

    term.success(&format!(
        "wallet and a new account successfully created.\n
        {}: {}\n\n",
        keyfile.account_name,
        keyfile.base64_address
    ))?;

    Ok(())
}

/// Add a new account
pub(crate) fn add_account<R: Rng>(term: &mut Term, root_dir: PathBuf, rng: &mut R) -> Result<()> {
    // 1. configure wallet directory
    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // 2. configure user-defined passoword
    term.info("Set a wallet password. This is for local use only. It allows you to protect your cached private key and prevents the creation of non-desired transactions.\n")?;
    let password = term.new_password("wallet password", "confirm wallet password", "password mismatch")?;

    // 3. generate the mnemonics
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = mnemonic.phrase();
    term.info("Please, note carefully the following mnemonic words. They will be needed to recover your wallet.\n")?;
    term.error(&format!("{}\n", phrase))?;

    // 4. enter new account name
    term.info("Enter a new account name.\n")?;
    let account_name = term.account_name("new account name")?;

    // 5. create keyfile
    let seed = Seed::new(&mnemonic, "");
    let seed_vec = seed.as_bytes();
    let mut keyfile = KeyFile::new_from_seed(
        account_name.as_str(),
        VERSION,
        &password,
        ITERS,
        &seed_vec,
        rng
    )?;

    // 6. store a keyfile
    keystore_dir.insert(&mut keyfile, rng)?;

    term.success(&format!(
        "wallet and a new account successfully created.\n
        {}: {}\n\n",
        keyfile.account_name,
        keyfile.base64_address
    ))?;

    Ok(())
}


pub(crate) fn show_list(
    term: &mut Term,
    root_dir: PathBuf,
) -> Result<()> {
    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    let keyfiles = keystore_dir.load_all()?;
    if keyfiles.len() == 0 {
        term.warn("Not found accounts\n")?;
        return Ok(());
    }

    // let default_index = get_default_index(&wallet_dir)? as usize;

    for (i, keyfile) in keyfiles.iter().enumerate() {
        let (name, address) = (&*keyfile.account_name, &*keyfile.base64_address);
        // if i == default_index {
            // term.success(&format!("* {}: {}\n", name, address))?;
        // } else {
            term.success(&format!("{}: {}\n", name, address))?;
        // }
    }

    Ok(())
}

fn wallet_keystore_dirs(root_dir: &PathBuf) -> Result<(WalletDirectory, KeystoreDirectory)> {
    // configure wallet directory
    let wallet_dir = WalletDirectory::create(&root_dir)?;

    // configure ketstore directory
    let keystore_dir_path = wallet_dir.get_default_keystore_dir();
    let keystore_dir = KeystoreDirectory::create(keystore_dir_path)?;

    Ok((wallet_dir, keystore_dir))
}

pub fn prompt_password(term: &mut Term) -> Result<Vec<u8>> {
    // enter password
    term.info("Enter the wallet passowrd.\n")?;
    let password = term.passowrd("wallet password")?;
    Ok(password)
}

pub fn get_keypair_from_keystore(root_dir: PathBuf, password: &[u8], keyfile_index: usize) -> Result<Keypair> {
    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;
    let keyfile = &keystore_dir.load_all()?[keyfile_index];
    let keypair = keyfile.get_key_pair(password)?;
    Ok(keypair)
}
