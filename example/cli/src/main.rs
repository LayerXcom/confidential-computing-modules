#[macro_use]
extern crate clap;

use std::{path::PathBuf, env};
use clap::{Arg, App, SubCommand, AppSettings, ArgMatches};
use rand::{rngs::OsRng, Rng};
use term::Term;
use anonify_common::UserAddress;
use crate::config::*;

mod term;
mod config;
mod commands;
mod error;

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

    let contract_addr = env::var("CONTRACT_ADDR").unwrap_or_else(|_| String::default());

    match matches.subcommand() {
        (ANONIFY_COMMAND, Some(matches)) => subcommand_anonify(term, root_dir, contract_addr, matches, rng),
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
const DEFAULT_STATE_ID: &str = "0";
const DEFAULT_TARGET: &str = "7H5cyDJ9CXBKOiM8tWnGaz5vqHY=";

fn subcommand_anonify<R: Rng>(
    mut term: Term,
    root_dir: PathBuf,
    default_contract_addr: String,
    matches: &ArgMatches,
    rng: &mut R
) {
    let anonify_url = env::var("ANONIFY_URL").expect("ANONIFY_URL is not set");

    match matches.subcommand() {
        ("deploy", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");

            commands::deploy(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                rng
            )
            .expect("Failed to deploy command");
        },
        ("register", Some(matches)) => {
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };

            commands::register(
                anonify_url,
                contract_addr,
            )
            .expect("Failed to register command");
        },
        ("init_state", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let total_supply: u64 = matches.value_of("total_supply")
                .expect("Not found total_supply.")
                .parse()
                .expect("Failed to parse total_supply");
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");

            commands::init_state(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                total_supply,
                state_id,
                contract_addr,
                rng
            )
            .expect("Failed to init_state command");
        },
        ("transfer", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches.value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");
            let target: &str = matches.value_of("target")
                .expect("Not found target");
            let target_addr = UserAddress::base64_decode(target);

            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");

            commands::transfer(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                target_addr,
                amount,
                state_id,
                contract_addr,
                rng
            )
            .expect("Failed to transfer command");
        },
        ("approve", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches.value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");
            let target: &str = matches.value_of("target")
                .expect("Not found target");
            let target_addr = UserAddress::base64_decode(target);

            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");

            commands::approve(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                target_addr,
                amount,
                state_id,
                contract_addr,
                rng
            )
                .expect("Failed to approve command");
        },
        ("transfer_from", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches.value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");
            let owner: &str = matches.value_of("owner")
                .expect("Not found owner");
            let owner_addr = UserAddress::base64_decode(owner);
            let target: &str = matches.value_of("target")
                .expect("Not found target");
            let target_addr = UserAddress::base64_decode(target);

            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");

            commands::transfer_from(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                owner_addr,
                target_addr,
                amount,
                state_id,
                contract_addr,
                rng
            )
                .expect("Failed to transfer_from command");
        },
        ("mint", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches.value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");
            let target: &str = matches.value_of("target")
                .expect("Not found target");
            let target_addr = UserAddress::base64_decode(target);

            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");

            commands::mint(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                target_addr,
                amount,
                state_id,
                contract_addr,
                rng
            )
                .expect("Failed to mint command");
        },
        ("burn", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let amount: u64 = matches.value_of("amount")
                .expect("Not found amount.")
                .parse()
                .expect("Failed to parse amount");

            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");

            commands::burn(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                amount,
                state_id,
                contract_addr,
                rng
            )
                .expect("Failed to burn command");
        },
        ("key_rotation", Some(matches)) => {
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };

            commands::key_rotation(
                anonify_url,
                contract_addr,
            )
            .expect("Failed to key_rotation command");
        },
        ("allowance", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");
            let spender = matches.value_of("spender")
                .expect("Not found spender");
            let spender_addr = UserAddress::base64_decode(spender);

            commands::allowance(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                state_id,
                spender_addr,
                contract_addr,
                rng
            )
            .expect("Failed allowance command");
        },
        ("balance_of", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");

            commands::balance_of(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                state_id,
                contract_addr,
                rng
            )
            .expect("Failed balance_of command");
        },
        ("start_polling", Some(matches)) => {
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };

            commands::start_polling(
                anonify_url,
                contract_addr,
            )
            .expect("Failed to start_polling command");
        },
        ("set_contract_addr", Some(matches)) => {
            let contract_addr = match matches.value_of("contract-addr") {
                Some(addr) => addr.to_string(),
                None => default_contract_addr,
            };

            commands::set_contract_addr(
                anonify_url,
                contract_addr,
            )
            .expect("Failed to set_contract_addr command");
        },
        _ => {
            term.error(matches.usage()).unwrap();
            std::process::exit(1);
        }
    };
}

fn anonify_commands_definition<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name(ANONIFY_COMMAND)
        .about("Anonify operations")
        .subcommand(SubCommand::with_name("deploy")
            .about("Deploy a contract from anonify services.")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
        )
        .subcommand(SubCommand::with_name("register")
            .about("register a contract from anonify services.")
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("init_state")
            .about("init_state from anonify services.")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
            .arg(Arg::with_name("total_supply")
                .short("t")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_BALANCE)
            )
            .arg(Arg::with_name("state_id")
                .short("s")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_STATE_ID)
            )
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("transfer")
            .about("Transfer the specified amount to the address")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
            .arg(Arg::with_name("amount")
                .short("a")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_AMOUNT)
            )
            .arg(Arg::with_name("state_id")
                .short("s")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_STATE_ID)
            )
            .arg(Arg::with_name("target")
                .short("to")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_TARGET)
            )
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("approve")
            .about("Approve the target address to spend token from owner's balance")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
            .arg(Arg::with_name("amount")
                .short("a")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_AMOUNT)
            )
            .arg(Arg::with_name("state_id")
                .short("s")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_STATE_ID)
            )
            .arg(Arg::with_name("target")
                .short("to")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_TARGET)
            )
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("transfer_from")
            .about("Transfer the specified amount to the target address from owner's address")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
            .arg(Arg::with_name("amount")
                .short("a")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_AMOUNT)
            )
            .arg(Arg::with_name("state_id")
                .short("s")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_STATE_ID)
            )
            .arg(Arg::with_name("owner")
                .short("from")
                .takes_value(true)
                .required(true)
            )
            .arg(Arg::with_name("target")
                .short("to")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_TARGET)
            )
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("mint")
            .about("Create new coins and assign to the target address")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
            .arg(Arg::with_name("amount")
                .short("a")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_AMOUNT)
            )
            .arg(Arg::with_name("state_id")
                .short("s")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_STATE_ID)
            )
            .arg(Arg::with_name("target")
                .short("to")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_TARGET)
            )
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("burn")
            .about("Create new coins and assign to the target address")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
            .arg(Arg::with_name("amount")
                .short("a")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_AMOUNT)
            )
            .arg(Arg::with_name("state_id")
                .short("s")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_STATE_ID)
            )
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("key_rotation")
            .about("handshake with other group members to rotate key")
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("allowance")
            .about("Get approved balance of the spender address from anonify services.")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
            .arg(Arg::with_name("state_id")
                .short("s")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_STATE_ID)
            )
            .arg(Arg::with_name("spender")
                .short("to")
                .takes_value(true)
                .required(true)
            )
        )
        .subcommand(SubCommand::with_name("balance_of")
            .about("Get balance of the address from anonify services.")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
            .arg(Arg::with_name("state_id")
                .short("s")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_STATE_ID)
            )
        )
        .subcommand(SubCommand::with_name("start_polling")
            .about("Get state from anonify services.")
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("set_contract_addr")
            .about("Get state from anonify services.")
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
            )
        )
}


//
// Wallet Sub Commands
//

const WALLET_COMMAND: &'static str = "wallet";

fn subcommand_wallet<R: Rng>(mut term: term::Term, root_dir: PathBuf, matches: &ArgMatches, rng: &mut R) {
    match matches.subcommand() {
        ("init", Some(_)) => {
            // Create new wallet
            commands::new_wallet(&mut term, root_dir, rng)
                .expect("Invalid operations of creating new wallet.");
        },
        ("add-account", Some(_)) => {
            // Create new wallet
            commands::add_account(&mut term, root_dir, rng)
                .expect("Invalid operations of Adding a new account.");
        },
        ("list", Some(_)) => {
            commands::show_list(&mut term, root_dir)
                .expect("Invalid operations of showing accounts list.");
        },
        _ => {
            term.error(matches.usage()).unwrap();
            ::std::process::exit(1)
        }
    };
}

fn wallet_commands_definition<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name(WALLET_COMMAND)
        .about("wallet operations")
        .subcommand(SubCommand::with_name("init")
            .about("Initialize your wallet.")
        )
        .subcommand(SubCommand::with_name("add-account")
            .about("Add a new account into your wallet.")
        )
        .subcommand(SubCommand::with_name("list")
            .about("Show list your accounts.")
        )
}
