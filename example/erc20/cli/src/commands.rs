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
use frame_treekem::{DhPubKey, EciesCiphertext};
use rand::Rng;
use reqwest::Client;
use serde_json::json;
use std::path::PathBuf;

pub(crate) fn deploy(anonify_url: String) -> Result<()> {
    let res = Client::new()
        .post(&format!("{}/api/v1/deploy", &anonify_url))
        .send()?
        .text()?;

    println!("Deployed Contract address: {}", res);
    Ok(())
}

pub(crate) fn join_group(anonify_url: String, contract_addr: String) -> Result<()> {
    let req = erc20_api::join_group::post::Request { contract_addr };
    let res = Client::new()
        .post(&format!("{}/api/v1/join_group", &anonify_url))
        .json(&req)
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn register_report(anonify_url: String, contract_addr: String) -> Result<()> {
    let req = erc20_api::register_report::post::Request { contract_addr };
    let res = Client::new()
        .post(&format!("{}/api/v1/register_report", &anonify_url))
        .json(&req)
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn update_mrenclave(anonify_url: String, contract_addr: String) -> Result<()> {
    let req = erc20_api::update_mrenclave::post::Request { contract_addr };
    let res = Client::new()
        .post(&format!("{}/api/v1/update_mrenclave", &anonify_url))
        .json(&req)
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn get_encrypting_key(anonify_url: String) -> Result<DhPubKey> {
    Client::new()
        .get(&format!("{}/api/v1/encrypting_key", &anonify_url))
        .send()?
        .json()
        .map_err(Into::into)
}

pub(crate) fn init_state<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    total_supply: u64,
    encrypting_key: &DhPubKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
    let req = json!({
        "access_policy": access_policy,
        "runtime_command": {
            "total_supply": total_supply,
        },
        "cmd_name": "construct",
    });
    let encrypted_req =
        EciesCiphertext::encrypt(&encrypting_key, serde_json::to_vec(&req).unwrap())
            .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &anonify_url))
        .json(&erc20_api::state::post::Request::new(encrypted_req))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn transfer<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    recipient: AccountId,
    amount: u64,
    encrypting_key: &DhPubKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
    let req = json!({
        "access_policy": access_policy,
        "runtime_command": {
            "amount": amount,
            "recipient": recipient,
        },
        "cmd_name": "transfer",
    });
    let encrypted_transfer_cmd =
        EciesCiphertext::encrypt(&encrypting_key, serde_json::to_vec(&req).unwrap())
            .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &anonify_url))
        .json(&erc20_api::state::post::Request::new(
            encrypted_transfer_cmd,
        ))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn approve<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    spender: AccountId,
    amount: u64,
    encrypting_key: &DhPubKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
    let req = json!({
        "access_policy": access_policy,
        "runtime_command": {
            "amount": amount,
            "spender": spender,
        },
        "cmd_name": "approve",
    });
    let encrypted_approve_cmd =
        EciesCiphertext::encrypt(&encrypting_key, serde_json::to_vec(&req).unwrap())
            .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &anonify_url))
        .json(&erc20_api::state::post::Request::new(encrypted_approve_cmd))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn transfer_from<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    owner: AccountId,
    recipient: AccountId,
    amount: u64,
    encrypting_key: &DhPubKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
    let req = json!({
        "access_policy": access_policy,
        "runtime_command": {
            "amount": amount,
            "owner": owner,
            "recipient": recipient,
        },
        "cmd_name": "transfer_from",
    });
    let encrypted_transfer_from_cmd =
        EciesCiphertext::encrypt(&encrypting_key, serde_json::to_vec(&req).unwrap())
            .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &anonify_url))
        .json(&erc20_api::state::post::Request::new(
            encrypted_transfer_from_cmd,
        ))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn mint<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    recipient: AccountId,
    amount: u64,
    encrypting_key: &DhPubKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
    let req = json!({
        "access_policy": access_policy,
        "runtime_command": {
            "amount": amount,
            "recipient": recipient,
        },
        "cmd_name": "mint",
    });
    let encrypted_mint_cmd =
        EciesCiphertext::encrypt(&encrypting_key, serde_json::to_vec(&req).unwrap())
            .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &anonify_url))
        .json(&erc20_api::state::post::Request::new(encrypted_mint_cmd))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn burn<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    amount: u64,
    encrypting_key: &DhPubKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);
    let req = json!({
        "access_policy": access_policy,
        "runtime_command": {
            "amount": amount,
        },
        "cmd_name": "burn",
    });
    let encrypted_burn_cmd =
        EciesCiphertext::encrypt(&encrypting_key, serde_json::to_vec(&req).unwrap())
            .map_err(|e| anyhow!("{:?}", e))?;

    let res = Client::new()
        .post(&format!("{}/api/v1/state", &anonify_url))
        .json(&erc20_api::state::post::Request::new(encrypted_burn_cmd))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);
    Ok(())
}

pub(crate) fn key_rotation(anonify_url: String) -> Result<()> {
    let res = Client::new()
        .post(&format!("{}/api/v1/key_rotation", &anonify_url))
        .send()?
        .text()?;

    println!("Transaction hash: {:?}", res);

    Ok(())
}

pub(crate) fn allowance<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    spender: AccountId,
    encrypting_key: &DhPubKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);

    let req = json!({
        "access_policy": access_policy,
        "runtime_command": {
            "spender": spender,
        },
        "state_name": "allowance",
    });
    let encrypted_req =
        EciesCiphertext::encrypt(&encrypting_key, serde_json::to_vec(&req).unwrap())
            .map_err(|e| anyhow!("{:?}", e))?;
    let res = Client::new()
        .get(&format!("{}/api/v1/allowance", &anonify_url))
        .json(&erc20_api::state::get::Request::new(encrypted_req))
        .send()?
        .text()?;

    println!("Current State: {:?}", res);
    Ok(())
}

pub(crate) fn balance_of<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    anonify_url: String,
    index: usize,
    encrypting_key: &DhPubKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let access_policy = Ed25519ChallengeResponse::new_from_keypair(keypair, rng);

    let req = json!({
        "access_policy": access_policy,
        "runtime_command": {},
        "state_name": "balance_of",
    });
    let encrypted_req =
        EciesCiphertext::encrypt(&encrypting_key, serde_json::to_vec(&req).unwrap())
            .map_err(|e| anyhow!("{:?}", e))?;
    let res = Client::new()
        .get(&format!("{}/api/v1/balance_of", &anonify_url))
        .json(&erc20_api::state::get::Request::new(encrypted_req))
        .send()?
        .text()?;

    println!("Current State: {:?}", res);
    Ok(())
}

pub(crate) fn start_sync_bc(anonify_url: String) -> Result<()> {
    Client::new()
        .get(&format!("{}/api/v1/start_sync_bc", &anonify_url))
        .send()?
        .text()?;

    Ok(())
}

pub(crate) fn set_contract_addr(anonify_url: String, contract_addr: String) -> Result<()> {
    let req = erc20_api::contract_addr::post::Request::new(contract_addr);
    Client::new()
        .get(&format!("{}/api/v1/set_contract_addr", &anonify_url))
        .json(&req)
        .send()?
        .text()?;

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
