use crate::{
    config::{ITERS, VERSION},
    error::Result,
    term::Term,
};
use anonify_wallet::{DirOperations, KeyFile, KeystoreDirectory, WalletDirectory};
use anyhow::anyhow;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use codec::Encode;
use ed25519_dalek::Keypair;
use erc20_state_transition::{approve, burn, construct, mint, transfer, transfer_from};
use frame_common::crypto::{AccountId, ClientCiphertext};
use frame_runtime::primitives::U64;
use rand::Rng;
use reqwest::Client;
use sodiumoxide::crypto::box_::{self, PublicKey as SodiumPublicKey};
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

pub(crate) fn get_encrypting_key(anonify_url: String) -> Result<SodiumPublicKey> {
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
    encrypting_key: &SodiumPublicKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let init_state = construct {
        total_supply: U64::from_raw(total_supply),
    };

    let (_, client_priv_key) = box_::gen_keypair();
    let encrypted_total_supply =
        ClientCiphertext::encrypt(encrypting_key, &client_priv_key, init_state.encode())?;

    let req = erc20_api::init_state::post::Request::new(&keypair, encrypted_total_supply, rng);
    let res = Client::new()
        .post(&format!("{}/api/v1/init_state", &anonify_url))
        .json(&req)
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
    encrypting_key: &SodiumPublicKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let transfer_cmd = transfer {
        amount: U64::from_raw(amount),
        recipient,
    };

    let (_, client_priv_key) = box_::gen_keypair();
    let encrypted_transfer_cmd =
        ClientCiphertext::encrypt(encrypting_key, &client_priv_key, transfer_cmd.encode())?;

    let req = erc20_api::transfer::post::Request::new(&keypair, encrypted_transfer_cmd, rng);
    let res = Client::new()
        .post(&format!("{}/api/v1/transfer", &anonify_url))
        .json(&req)
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
    encrypting_key: &SodiumPublicKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let approve_cmd = approve {
        amount: U64::from_raw(amount),
        spender,
    };

    let (_, client_priv_key) = box_::gen_keypair();
    let encrypted_approve_cmd =
        ClientCiphertext::encrypt(encrypting_key, &client_priv_key, approve_cmd.encode())?;

    let req = erc20_api::approve::post::Request::new(&keypair, encrypted_approve_cmd, rng);
    let res = Client::new()
        .post(&format!("{}/api/v1/approve", &anonify_url))
        .json(&req)
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
    encrypting_key: &SodiumPublicKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let transfer_from_cmd = transfer_from {
        amount: U64::from_raw(amount),
        owner,
        recipient,
    };

    let (_, client_priv_key) = box_::gen_keypair();
    let encrypted_transfer_from_cmd =
        ClientCiphertext::encrypt(encrypting_key, &client_priv_key, transfer_from_cmd.encode())?;

    let req =
        erc20_api::transfer_from::post::Request::new(&keypair, encrypted_transfer_from_cmd, rng);
    let res = Client::new()
        .post(&format!("{}/api/v1/transfer_from", &anonify_url))
        .json(&req)
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
    encrypting_key: &SodiumPublicKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let mint_cmd = mint {
        amount: U64::from_raw(amount),
        recipient,
    };

    let (_, client_priv_key) = box_::gen_keypair();
    let encrypted_mint_cmd =
        ClientCiphertext::encrypt(encrypting_key, &client_priv_key, mint_cmd.encode())?;

    let req = erc20_api::mint::post::Request::new(&keypair, encrypted_mint_cmd, rng);
    let res = Client::new()
        .post(&format!("{}/api/v1/mint", &anonify_url))
        .json(&req)
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
    encrypting_key: &SodiumPublicKey,
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;
    let burn_cmd = burn {
        amount: U64::from_raw(amount),
    };

    let (_, client_priv_key) = box_::gen_keypair();
    let encrypted_burn_cmd =
        ClientCiphertext::encrypt(encrypting_key, &client_priv_key, burn_cmd.encode())?;

    let req = erc20_api::burn::post::Request::new(&keypair, encrypted_burn_cmd, rng);
    let res = Client::new()
        .post(&format!("{}/api/v1/burn", &anonify_url))
        .json(&req)
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
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;

    let req = erc20_api::allowance::get::Request::new(&keypair, spender, rng);
    let res = Client::new()
        .get(&format!("{}/api/v1/allowance", &anonify_url))
        .json(&req)
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
    rng: &mut R,
) -> Result<()> {
    let password = prompt_password(term)?;
    let keypair = get_keypair_from_keystore(root_dir, &password, index)?;

    let req = erc20_api::state::get::Request::new(&keypair, rng);
    let res = Client::new()
        .get(&format!("{}/api/v1/balance_of", &anonify_url))
        .json(&req)
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
