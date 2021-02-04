#[macro_use]
extern crate clap;

use crate::config::*;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use frame_common::crypto::AccountId;
use frame_runtime::primitives::Bytes;
use frame_sodium::SodiumPubKey;
use rand::{rngs::OsRng, Rng};
use rand_core::{CryptoRng, RngCore};
use std::io::Read;
use std::{env, fs::File, path::PathBuf};
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

    let contract_addr = env::var("CONTRACT_ADDR").unwrap_or_else(|_| String::default());
    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set");
    let enclave_encryption_key = commands::get_enclave_encryption_key(anonify_url.clone())
        .expect("Failed getting encryption key");

    match matches.subcommand() {
        (ANONIFY_COMMAND, Some(matches)) => subcommand_anonify(
            term,
            root_dir,
            contract_addr,
            &enclave_encryption_key,
            anonify_url,
            matches,
            rng,
            &mut csprng,
        ),
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
    default_contract_addr: String,
    enclave_encryption_key: &SodiumPubKey,
    anonify_url: String,
    matches: &ArgMatches,
    rng: &mut R,
    csprng: &mut CR,
) where
    R: Rng,
    CR: RngCore + CryptoRng,
{
    match matches.subcommand() {
        ("deploy", Some(_)) => {
            commands::deploy(anonify_url).expect("Failed to deploy command");
        }
        ("join_group", Some(matches)) => {
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };

            commands::join_group(anonify_url, contract_addr).expect("Failed to join_group command");
        }
        ("register_report", Some(matches)) => {
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };

            commands::register_report(anonify_url, contract_addr)
                .expect("Failed to register_report command");
        }
        ("update_mrenclave", Some(matches)) => {
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };

            commands::update_mrenclave(anonify_url, contract_addr)
                .expect("Failed to update_mrenclave command");
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

            commands::init_state(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                total_supply,
                enclave_encryption_key,
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

            commands::transfer(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                target_addr,
                amount,
                enclave_encryption_key,
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

            commands::approve(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                target_addr,
                amount,
                enclave_encryption_key,
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

            commands::transfer_from(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                owner_addr,
                target_addr,
                amount,
                enclave_encryption_key,
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

            commands::mint(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                target_addr,
                amount,
                enclave_encryption_key,
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

            commands::burn(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                amount,
                enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed to burn command");
        }
        ("key_rotation", Some(_)) => {
            commands::key_rotation(anonify_url).expect("Failed to key_rotation command");
        }
        ("allowance", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let spender = matches.value_of("spender").expect("Not found spender");
            let spender_addr = AccountId::base64_decode(spender);

            commands::allowance(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                spender_addr,
                enclave_encryption_key,
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

            commands::balance_of(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed balance_of command");
        }
        ("start_sync_bc", Some(_)) => {
            commands::start_sync_bc(anonify_url).expect("Failed to start_sync_bc command");
        }
        ("set_contract_address", Some(matches)) => {
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };

            commands::set_contract_address(anonify_url, contract_addr)
                .expect("Failed to set_contract_address command");
        }
        ("append_blob", Some(matches)) => {
            let keyfile_index: usize = matches
                .value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let blob_path = matches.value_of("blob").expect("Not found spender");

            let mut buf = vec![];
            let mut f = File::open(blob_path).unwrap();
            f.read_to_end(&mut buf).unwrap();
            let blob = Bytes::new(buf);

            commands::append_blob(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                blob,
                enclave_encryption_key,
                rng,
                csprng,
            )
            .expect("Failed to burn command");
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
            SubCommand::with_name("deploy").about("Deploy a contract from anonify services."),
        )
        .subcommand(
            SubCommand::with_name("join_group")
                .about("join group a contract from anonify services.")
                .arg(Arg::with_name("contract-addr").short("c").takes_value(true)),
        )
        .subcommand(
            SubCommand::with_name("register_report")
                .about("register a report to the blockchain")
                .arg(Arg::with_name("contract-addr").short("c").takes_value(true)),
        )
        .subcommand(
            SubCommand::with_name("update_mrenclave")
                .about("update mrenclave a contract from anonify services.")
                .arg(Arg::with_name("contract-addr").short("c").takes_value(true)),
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
                ),
        )
        .subcommand(
            SubCommand::with_name("start_sync_bc").about("Get state from anonify services."),
        )
        .subcommand(
            SubCommand::with_name("set_contract_address")
                .about("Get state from anonify services.")
                .arg(Arg::with_name("contract-addr").short("c").takes_value(true)),
        )
        .subcommand(
            SubCommand::with_name("append_blob")
                .about("append bytes to Bytes in enclave for performance measurement")
                .arg(
                    Arg::with_name("keyfile-index")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value(DEFAULT_KEYFILE_INDEX),
                )
                .arg(
                    Arg::with_name("blob")
                        .short("b")
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
