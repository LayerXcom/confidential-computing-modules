#[macro_use]
extern crate clap;

use crate::config::*;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use frame_common::crypto::AccountId;
use frame_sodium::SodiumPubKey;
use rand::{rngs::OsRng, Rng};
use rand_core::{CryptoRng, RngCore};
use std::{env, path::PathBuf};
use term::Term;

mod commands;
mod config;
mod error;
mod term;

fn main() {
    let default_root_dir = get_default_root_dir();

    let matches = App::new("anonify")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version(crate_version!())
        .author(crate_authors!())
        .about("Anonify's command line interface")
        .arg(global_verbose_definition())
        .arg(global_quiet_definition())
        .arg(global_color_definition())
        .arg(global_rootdir_definition(&default_root_dir))
        .subcommand(anonify_commands_definition())
        .subcommand(wallet_commands_definition())
        .get_matches();

    let mut term = term::Term::new(config_terminal(&matches));
    let root_dir = global_rootdir_match(&default_root_dir, &matches);
    let rng = &mut OsRng;
    // just for testing
    let mut csprng = rand::thread_rng();
    let state_runtime_url = env::var("STATE_RUNTIME_URL").expect("STATE_RUNTIME_URL is not set");

    match matches.subcommand() {
        (ANONIFY_COMMAND, Some(matches)) => {
            subcommand_anonify(term, root_dir, state_runtime_url, matches, rng, &mut csprng)
        }
        (WALLET_COMMAND, Some(matches)) => subcommand_wallet(term, root_dir, matches, rng),
        _ => {
            term.error(matches.usage()).unwrap();
            std::process::exit(1);
        }
    }
}

//
// Anonify Sub Commands
//

const ANONIFY_COMMAND: &'static str = "anonify";
const DEFAULT_KEYFILE_INDEX: &'static str = "0";
const DEFAULT_AMOUNT: &str = "10";
const DEFAULT_BALANCE: &str = "100";
const DEFAULT_TARGET: &str = "7H5cyDJ9CXBKOiM8tWnGaz5vqHY=";

fn subcommand_anonify<R, CR>(
    mut term: Term,
    root_dir: PathBuf,
    state_runtime_url: String,
    matches: &ArgMatches,
    rng: &mut R,
    csprng: &mut CR,
) where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    match matches.subcommand() {
        ("register_report", Some(_)) => {
            commands::register_report(state_runtime_url)
                .expect("Failed to register_report command");
        }
        ("init_state", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let total_supply: u64 = matches
                .value_of("total_supply")
                .expect("Not found total_supply.")
                .parse()
                .expect("Failed to parse total_supply");
            let enclave_encryption_key_vec = base64::decode(
                matches
                    .value_of("enclave_encryption_key")
                    .expect("Not found enclave_encryption_key"),
            )
            .expect("Failed to decode enclave_encryption_key as base64");
            let enclave_encryption_key = SodiumPubKey::from_bytes(&enclave_encryption_key_vec)
                .expect("Failed to convert SodiumPubKey");

            commands::init_state(
                &mut term,
                root_dir,
                state_runtime_url,
                keyfile_index,
                total_supply,
                &enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed to init_state command");
        }
        ("transfer", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches
                .value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");
            let target: &str = matches.value_of("target").expect("Not found target");
            let target_addr = AccountId::base64_decode(target);
            let enclave_encryption_key_vec = base64::decode(
                matches
                    .value_of("enclave_encryption_key")
                    .expect("Not found enclave_encryption_key"),
            )
            .expect("Failed to decode enclave_encryption_key as base64");
            let enclave_encryption_key = SodiumPubKey::from_bytes(&enclave_encryption_key_vec)
                .expect("Failed to convert SodiumPubKey");

            commands::transfer(
                &mut term,
                root_dir,
                state_runtime_url,
                keyfile_index,
                target_addr,
                amount,
                &enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed to transfer command");
        }
        ("approve", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches
                .value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");
            let target: &str = matches.value_of("target").expect("Not found target");
            let target_addr = AccountId::base64_decode(target);
            let enclave_encryption_key_vec = base64::decode(
                matches
                    .value_of("enclave_encryption_key")
                    .expect("Not found enclave_encryption_key"),
            )
            .expect("Failed to decode enclave_encryption_key as base64");
            let enclave_encryption_key = SodiumPubKey::from_bytes(&enclave_encryption_key_vec)
                .expect("Failed to convert SodiumPubKey");

            commands::approve(
                &mut term,
                root_dir,
                state_runtime_url,
                keyfile_index,
                target_addr,
                amount,
                &enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed to approve command");
        }
        ("transfer_from", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches
                .value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");
            let owner: &str = matches.value_of("owner").expect("Not found owner");
            let owner_addr = AccountId::base64_decode(owner);
            let target: &str = matches.value_of("target").expect("Not found target");
            let target_addr = AccountId::base64_decode(target);
            let enclave_encryption_key_vec = base64::decode(
                matches
                    .value_of("enclave_encryption_key")
                    .expect("Not found enclave_encryption_key"),
            )
            .expect("Failed to decode enclave_encryption_key as base64");
            let enclave_encryption_key = SodiumPubKey::from_bytes(&enclave_encryption_key_vec)
                .expect("Failed to convert SodiumPubKey");

            commands::transfer_from(
                &mut term,
                root_dir,
                state_runtime_url,
                keyfile_index,
                owner_addr,
                target_addr,
                amount,
                &enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed to transfer_from command");
        }
        ("mint", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches
                .value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");
            let target: &str = matches.value_of("target").expect("Not found target");
            let target_addr = AccountId::base64_decode(target);
            let enclave_encryption_key_vec = base64::decode(
                matches
                    .value_of("enclave_encryption_key")
                    .expect("Not found enclave_encryption_key"),
            )
            .expect("Failed to decode enclave_encryption_key as base64");
            let enclave_encryption_key = SodiumPubKey::from_bytes(&enclave_encryption_key_vec)
                .expect("Failed to convert SodiumPubKey");

            commands::mint(
                &mut term,
                root_dir,
                state_runtime_url,
                keyfile_index,
                target_addr,
                amount,
                &enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed to mint command");
        }
        ("burn", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches
                .value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");
            let enclave_encryption_key_vec = base64::decode(
                matches
                    .value_of("enclave_encryption_key")
                    .expect("Not found enclave_encryption_key"),
            )
            .expect("Failed to decode enclave_encryption_key as base64");
            let enclave_encryption_key = SodiumPubKey::from_bytes(&enclave_encryption_key_vec)
                .expect("Failed to convert SodiumPubKey");

            commands::burn(
                &mut term,
                root_dir,
                state_runtime_url,
                keyfile_index,
                amount,
                &enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed to burn command");
        }
        ("key_rotation", Some(_)) => {
            commands::key_rotation(state_runtime_url).expect("Failed to key_rotation command");
        }
        ("allowance", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let spender = matches.value_of("spender").expect("Not found spender");
            let spender_addr = AccountId::base64_decode(spender);
            let enclave_encryption_key_vec = base64::decode(
                matches
                    .value_of("enclave_encryption_key")
                    .expect("Not found enclave_encryption_key"),
            )
            .expect("Failed to decode enclave_encryption_key as base64");
            let enclave_encryption_key = SodiumPubKey::from_bytes(&enclave_encryption_key_vec)
                .expect("Failed to convert SodiumPubKey");

            commands::allowance(
                &mut term,
                root_dir,
                state_runtime_url,
                keyfile_index,
                spender_addr,
                &enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed allowance command");
        }
        ("balance_of", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let enclave_encryption_key_vec = base64::decode(
                matches
                    .value_of("enclave_encryption_key")
                    .expect("Not found enclave_encryption_key"),
            )
            .expect("Failed to decode enclave_encryption_key as base64");
            let enclave_encryption_key = SodiumPubKey::from_bytes(&enclave_encryption_key_vec)
                .expect("Failed to convert SodiumPubKey");

            commands::balance_of(
                &mut term,
                root_dir,
                state_runtime_url,
                keyfile_index,
                &enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed balance_of command");
        }
        ("get_enclave_encryption_key", Some(_)) => {
            let enclave_encryption_key =
                commands::get_enclave_encryption_key(state_runtime_url.clone())
                    .expect("Failed getting encryption key");
            let encoded = base64::encode(&enclave_encryption_key.to_bytes());
            println!("{:?}", encoded);
        }
        ("get_user_counter", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let enclave_encryption_key_vec = base64::decode(
                matches
                    .value_of("enclave_encryption_key")
                    .expect("Not found enclave_encryption_key"),
            )
            .expect("Failed to decode enclave_encryption_key as base64");
            let enclave_encryption_key = SodiumPubKey::from_bytes(&enclave_encryption_key_vec)
                .expect("Failed to convert SodiumPubKey");

            let user_counter = commands::get_user_counter(
                &mut term,
                root_dir,
                state_runtime_url,
                keyfile_index,
                &enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed getting user counter");

            println!("{:?}", user_counter);
        }
        _ => {
            term.error(matches.usage()).unwrap();
            std::process::exit(1);
        }
    };
}

fn anonify_commands_definition<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name(ANONIFY_COMMAND)
        .about("Anonify operations")
        .subcommand(
            SubCommand::with_name("register_report").about("register a report to the blockchain"),
        )
        .subcommand(
            SubCommand::with_name("init_state")
                .about("init_state from anonify services.")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("total_supply")
                        .short("t")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_BALANCE),
                )
                .arg(
                    Arg::with_name("enclave_encryption_key")
                        .short("k")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("transfer")
                .about("Transfer the specified amount to the address")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_AMOUNT),
                )
                .arg(
                    Arg::with_name("target")
                        .short("to")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_TARGET),
                )
                .arg(
                    Arg::with_name("enclave_encryption_key")
                        .short("k")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("approve")
                .about("Approve the target address to spend token from owner's balance")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_AMOUNT),
                )
                .arg(
                    Arg::with_name("target")
                        .short("to")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_TARGET),
                )
                .arg(
                    Arg::with_name("enclave_encryption_key")
                        .short("k")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("transfer_from")
                .about("Transfer the specified amount to the target address from owner's address")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_AMOUNT),
                )
                .arg(
                    Arg::with_name("owner")
                        .short("from")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("target")
                        .short("to")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_TARGET),
                )
                .arg(
                    Arg::with_name("enclave_encryption_key")
                        .short("k")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("mint")
                .about("Create new coins and assign to the target address")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_AMOUNT),
                )
                .arg(
                    Arg::with_name("target")
                        .short("to")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_TARGET),
                )
                .arg(
                    Arg::with_name("enclave_encryption_key")
                        .short("k")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("burn")
                .about("Burn the coins")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .takes_value(true)
                        .required(true)
                        .default_value(DEFAULT_AMOUNT),
                )
                .arg(
                    Arg::with_name("enclave_encryption_key")
                        .short("k")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("key_rotation")
                .about("handshake with other group members to rotate key"),
        )
        .subcommand(
            SubCommand::with_name("allowance")
                .about("Get approved balance of the spender address from anonify services.")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("spender")
                        .short("to")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("enclave_encryption_key")
                        .short("k")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("balance_of")
                .about("Get balance of the address from anonify services.")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("enclave_encryption_key")
                        .short("k")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("get_enclave_encryption_key")
                .about("Get base64 encoded enclave_encryption_key"),
        )
        .subcommand(
            SubCommand::with_name("get_user_counter")
                .about("Get current user_counter")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("enclave_encryption_key")
                        .short("k")
                        .takes_value(true)
                        .required(true),
                ),
        )
}

//
// Wallet Sub Commands
//

const WALLET_COMMAND: &'static str = "wallet";

fn subcommand_wallet<R: Rng>(
    mut term: term::Term,
    root_dir: PathBuf,
    matches: &ArgMatches,
    rng: &mut R,
) {
    match matches.subcommand() {
        ("init", Some(_)) => {
            // Create new wallet
            commands::new_wallet(&mut term, root_dir, rng)
                .expect("Invalid operations of creating new wallet.");
        }
        ("add-account", Some(_)) => {
            // Create new wallet
            commands::add_account(&mut term, root_dir, rng)
                .expect("Invalid operations of Adding a new account.");
        }
        ("list", Some(_)) => {
            commands::show_list(&mut term, root_dir)
                .expect("Invalid operations of showing accounts list.");
        }
        _ => {
            term.error(matches.usage()).unwrap();
            ::std::process::exit(1)
        }
    };
}

fn wallet_commands_definition<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name(WALLET_COMMAND)
        .about("wallet operations")
        .subcommand(SubCommand::with_name("init").about("Initialize your wallet."))
        .subcommand(
            SubCommand::with_name("add-account").about("Add a new account into your wallet."),
        )
        .subcommand(SubCommand::with_name("list").about("Show list your accounts."))
}
