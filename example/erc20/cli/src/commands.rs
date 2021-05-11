use crate::{
    config::{ITERS, VERSION},
    error::Result,
    term::Term,
};
use anonify_wallet::{DirOperations, KeyFile, KeystoreDirectory, WalletDirectory};
use anyhow::anyhow;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use ed25519_dalek::Keypair;
use frame_common::crypto::{AccountId, Ed25519ChallengeResponse};
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

pub(crate) fn get_user_counter<R, CR>(
    term: &mut Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    index: usize,
    enclave_encryption_key: &SodiumPubKey,
    rng: &mut R,
    csprng: &mut CR,
) -> Result<u32>
where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);

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

pub(crate) fn init_state<R, CR>(
    term: &mut Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    index: usize,
    total_supply: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    rng: &mut R,
    csprng: &mut CR,
) -> Result<()>
where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
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

pub(crate) fn transfer<R, CR>(
    term: &mut Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    index: usize,
    recipient: AccountId,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    rng: &mut R,
    csprng: &mut CR,
) -> Result<()>
where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
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

pub(crate) fn approve<R, CR>(
    term: &mut Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    index: usize,
    spender: AccountId,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    rng: &mut R,
    csprng: &mut CR,
) -> Result<()>
where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
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

pub(crate) fn transfer_from<R, CR>(
    term: &mut Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    index: usize,
    owner: AccountId,
    recipient: AccountId,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    rng: &mut R,
    csprng: &mut CR,
) -> Result<()>
where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
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

pub(crate) fn mint<R, CR>(
    term: &mut Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    index: usize,
    recipient: AccountId,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    rng: &mut R,
    csprng: &mut CR,
) -> Result<()>
where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
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

pub(crate) fn burn<R, CR>(
    term: &mut Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    index: usize,
    amount: u64,
    counter: u32,
    enclave_encryption_key: &SodiumPubKey,
    rng: &mut R,
    csprng: &mut CR,
) -> Result<()>
where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
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

pub(crate) fn allowance<R, CR>(
    term: &mut Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    index: usize,
    spender: AccountId,
    enclave_encryption_key: &SodiumPubKey,
    rng: &mut R,
    csprng: &mut CR,
) -> Result<()>
where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);

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

pub(crate) fn balance_of<R, CR>(
    term: &mut Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    index: usize,
    enclave_encryption_key: &SodiumPubKey,
    rng: &mut R,
    csprng: &mut CR,
) -> Result<()>
where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);

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

pub fn prompt_password(term: &mut Term) -> Result<Vec<u8>> {
    // enter password
    term.info("Enter the wallet password.\n")?;
    let password = term.password("wallet password")?;
    Ok(password)
}

pub fn get_keypair_from_keystore(
    root_dir: PathBuf,
    password: &[u8],
    keyfile_index: usize,
) -> Result<Keypair> {
    let (_wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;
    let keyfile = &keystore_dir.load_all()?[keyfile_index];
    let keypair = keyfile.get_key_pair(password)?;
    Ok(keypair)
}
