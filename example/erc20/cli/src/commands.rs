use crate::{
    config::{ITERS, VERSION},
    error::Result,
    term::Term,
};
use anonify_wallet::{DirOperations, KeyFile, KeystoreDirectory, WalletDirectory};
use anyhow::anyhow;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use frame_common::crypto::{AccountId, NoAuth, ACCOUNT_ID_SIZE};
use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use reqwest::Client;
use serde_json::json;
use std::path::PathBuf;

pub(crate) fn register_report(state_runtime_url: String) -> Result<()> {
    let res = Client::new()
        .post(&format!("{}/api/v1/register_report", &state_runtime_url))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn get_enclave_encryption_key(state_runtime_url: String) -> Result<SodiumPubKey> {
    let resp: state_runtime_node_api::enclave_encryption_key::get::Response = Client::new()
        .get(&format!(
            "{}/api/v1/enclave_encryption_key",
            &state_runtime_url
        ))
        .send()?
        .json()?;

    Ok(resp.enclave_encryption_key)
}

pub(crate) fn get_user_counter<CR>(
    state_runtime_url: String,
    enclave_encryption_key: &SodiumPubKey,
    csprng: &mut CR,
) -> Result<u32>
where
    CR: RngCore + CryptoRng,
{
    let access_policy = NoAuth::new(generate_account_id_from_rng());

    let req = json!({
        "access_policy": access_policy,
    });
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key,
        &serde_json::to_vec(&req).unwrap(),
    )
    .map_err(|e| anyhow!("{:?}", e))?;

    let resp: state_runtime_node_api::user_counter::get::Response = Client::new()
        .get(&format!("{}/api/v1/user_counter", &state_runtime_url))
        .json(&state_runtime_node_api::user_counter::get::Request::new(
            ciphertext,
        ))
        .send()?
        .json()?;

    let user_counter = resp
        .user_counter
        .as_u64()
        .ok_or_else(|| anyhow!("failed to parse user_counter"))?;

    Ok(user_counter as u32)
}

pub(crate) fn init_state<CR>(
    state_runtime_url: String,
    total_supply: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    csprng: &mut CR,
) -> Result<()>
where
    CR: RngCore + CryptoRng,
{
    let access_policy = NoAuth::new(generate_account_id_from_rng());
    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
        "counter": counter,
    });
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key,
        &serde_json::to_vec(&req).unwrap(),
    )
    .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &state_runtime_url))
        .json(&state_runtime_node_api::state::post::Request::new(
            ciphertext,
        ))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn transfer<CR>(
    state_runtime_url: String,
    recipient: AccountId,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    csprng: &mut CR,
) -> Result<()>
where
    CR: RngCore + CryptoRng,
{
    let access_policy = NoAuth::new(generate_account_id_from_rng());
    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "amount": amount,
            "recipient": recipient,
        },
        "cmd_name": "transfer",
        "counter": counter,
    });
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key,
        &serde_json::to_vec(&req).unwrap(),
    )
    .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &state_runtime_url))
        .json(&state_runtime_node_api::state::post::Request::new(
            ciphertext,
        ))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn approve<CR>(
    state_runtime_url: String,
    spender: AccountId,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    csprng: &mut CR,
) -> Result<()>
where
    CR: RngCore + CryptoRng,
{
    let access_policy = NoAuth::new(generate_account_id_from_rng());
    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "amount": amount,
            "spender": spender,
        },
        "cmd_name": "approve",
        "counter": counter,
    });
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key,
        &serde_json::to_vec(&req).unwrap(),
    )
    .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &state_runtime_url))
        .json(&state_runtime_node_api::state::post::Request::new(
            ciphertext,
        ))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn transfer_from<CR>(
    state_runtime_url: String,
    owner: AccountId,
    recipient: AccountId,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    csprng: &mut CR,
) -> Result<()>
where
    CR: RngCore + CryptoRng,
{
    let access_policy = NoAuth::new(generate_account_id_from_rng());
    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "amount": amount,
            "owner": owner,
            "recipient": recipient,
        },
        "cmd_name": "transfer_from",
        "counter": counter,
    });
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key,
        &serde_json::to_vec(&req).unwrap(),
    )
    .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &state_runtime_url))
        .json(&state_runtime_node_api::state::post::Request::new(
            ciphertext,
        ))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn mint<CR>(
    state_runtime_url: String,
    recipient: AccountId,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    csprng: &mut CR,
) -> Result<()>
where
    CR: RngCore + CryptoRng,
{
    let access_policy = NoAuth::new(generate_account_id_from_rng());
    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "amount": amount,
            "recipient": recipient,
        },
        "cmd_name": "mint",
        "counter": counter,
    });
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key,
        &serde_json::to_vec(&req).unwrap(),
    )
    .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &state_runtime_url))
        .json(&state_runtime_node_api::state::post::Request::new(
            ciphertext,
        ))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn burn<CR>(
    state_runtime_url: String,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    csprng: &mut CR,
) -> Result<()>
where
    CR: RngCore + CryptoRng,
{
    let access_policy = NoAuth::new(generate_account_id_from_rng());
    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "amount": amount,
        },
        "cmd_name": "burn",
        "counter": counter,
    });
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key,
        &serde_json::to_vec(&req).unwrap(),
    )
    .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &state_runtime_url))
        .json(&state_runtime_node_api::state::post::Request::new(
            ciphertext,
        ))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn key_rotation(state_runtime_url: String) -> Result<()> {
    let res = Client::new()
        .post(&format!("{}/api/v1/key_rotation", &state_runtime_url))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);

    Ok(())
}

pub(crate) fn allowance<CR>(
    state_runtime_url: String,
    spender: AccountId,
    enclave_encryption_key: &SodiumPubKey,
    csprng: &mut CR,
) -> Result<()>
where
    CR: RngCore + CryptoRng,
{
    let access_policy = NoAuth::new(generate_account_id_from_rng());

    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {
            "spender": spender,
        },
        "state_name": "allowance",
    });
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key,
        &serde_json::to_vec(&req).unwrap(),
    )
    .map_err(|e| anyhow!("{:?}", e))?;
    let res = Client::new()
        .get(&format!("{}/api/v1/state", &state_runtime_url))
        .json(&state_runtime_node_api::state::get::Request::new(
            ciphertext,
        ))
        .send()?
        .text()?;

    println!("Current State: {:?}", res);
    Ok(())
}

pub(crate) fn balance_of<CR>(
    state_runtime_url: String,
    enclave_encryption_key: &SodiumPubKey,
    csprng: &mut CR,
) -> Result<()>
where
    CR: RngCore + CryptoRng,
{
    let access_policy = NoAuth::new(generate_account_id_from_rng());

    let req = json!({
        "access_policy": access_policy,
        "runtime_params": {},
        "state_name": "balance_of",
    });
    let ciphertext = SodiumCiphertext::encrypt(
        csprng,
        &enclave_encryption_key,
        &serde_json::to_vec(&req).unwrap(),
    )
    .map_err(|e| anyhow!("{:?}", e))?;
    let res = Client::new()
        .get(&format!("{}/api/v1/state", &state_runtime_url))
        .json(&state_runtime_node_api::state::get::Request::new(
            ciphertext,
        ))
        .send()?
        .text()?;

    println!("Current State: {:?}", res);
    Ok(())
}

/// Create a new wallet
pub(crate) fn new_wallet<R: Rng>(term: &mut Term, root_dir: PathBuf, rng: &mut R) -> Result<()> {
    // 1. configure wallet directory
    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // 2. configure user-defined password
    term.info("Set a wallet password. This is for local use only. It allows you to protect your cached private key and prevents the creation of non-desired transactions.\n")?;
    let password = term.new_password(
        "wallet password",
        "confirm wallet password",
        "password mismatch",
    )?;

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
        rng,
    )?;

    // 6. store a keyfile
    keystore_dir.insert(&mut keyfile, rng)?;

    term.success(&format!(
        "wallet and a new account successfully created.\n
        {}: {}\n\n",
        keyfile.account_name, keyfile.base64_address
    ))?;

    Ok(())
}

/// Add a new account
pub(crate) fn add_account<R: Rng>(term: &mut Term, root_dir: PathBuf, rng: &mut R) -> Result<()> {
    // 1. configure wallet directory
    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // 2. configure user-defined password
    term.info("Set a wallet password. This is for local use only. It allows you to protect your cached private key and prevents the creation of non-desired transactions.\n")?;
    let password = term.new_password(
        "wallet password",
        "confirm wallet password",
        "password mismatch",
    )?;

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
        rng,
    )?;

    // 6. store a keyfile
    keystore_dir.insert(&mut keyfile, rng)?;

    term.success(&format!(
        "wallet and a new account successfully created.\n
        {}: {}\n\n",
        keyfile.account_name, keyfile.base64_address
    ))?;

    Ok(())
}

pub(crate) fn show_list(term: &mut Term, root_dir: PathBuf) -> Result<()> {
    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    let keyfiles = keystore_dir.load_all()?;
    if keyfiles.len() == 0 {
        term.warn("Not found accounts\n")?;
        return Ok(());
    }

    // let default_index = get_default_index(&wallet_dir)? as usize;

    for (_i, keyfile) in keyfiles.iter().enumerate() {
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

pub fn generate_account_id_from_rng() -> AccountId {
    let array = rand::thread_rng().gen::<[u8; ACCOUNT_ID_SIZE]>();
    AccountId::from_array(array)
}