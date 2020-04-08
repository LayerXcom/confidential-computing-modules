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

    match matches.subcommand() {
        (ANONIFY_COMMAND, Some(matches)) => subcommand_anonify(term, root_dir, matches, rng),
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
const DEFAULT_CONTRACT_ADDRESS: &'static str = "580bc66c83f54056bb337a75eae8e424e96f32de";
const DEFAULT_AMOUNT: &str = "10";
const DEFAULT_BALANCE: &str = "100";
const DEFAULT_STATE_ID: &str = "0";
const DEFAULT_TARGET: &str = "7H5cyDJ9CXBKOiM8tWnGaz5vqHY=";

fn subcommand_anonify<R: Rng>(
    mut term: Term,
    root_dir: PathBuf,
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
            let contract_addr = matches.value_of("contract-addr")
                .expect("Not found contract-addr")
                .to_string();

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
            let contract_addr = matches.value_of("contract-addr")
                .expect("Not found contract-addr")
                .to_string();
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
        ("state_transition", Some(matches)) => {
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

            let contract_addr = matches.value_of("contract-addr")
                .expect("Not found contract-addr")
                .to_string();
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");

            commands::state_transition(
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
            .expect("Failed to state_transition command");
        },
        ("handshake", Some(matches)) => {
            let contract_addr = matches.value_of("contract-addr")
                .expect("Not found contract-addr")
                .to_string();

            commands::handshake(
                anonify_url,
                contract_addr,
            )
            .expect("Failed to handshake command");
        },
        ("get_state", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let contract_addr = matches.value_of("contract-addr")
                .expect("Not found contract-addr")
                .to_string();
            let state_id = matches.value_of("state_id")
                .expect("Not found state_id")
                .parse()
                .expect("Failed to parse state_id");

            commands::get_state(
                &mut term,
                root_dir,
                anonify_url,
                keyfile_index,
                state_id,
                contract_addr,
                rng
            )
            .expect("Failed to get state command");
        },
        ("start_polling", Some(matches)) => {
            let contract_addr = matches.value_of("contract-addr")
                .expect("Not found contract-addr")
                .to_string();

            commands::start_polling(
                anonify_url,
                contract_addr,
            )
            .expect("Failed to start_polling command");
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
                .required(true)
                .default_value(DEFAULT_CONTRACT_ADDRESS)
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
                .required(true)
                .default_value(DEFAULT_CONTRACT_ADDRESS)
            )
        )
        .subcommand(SubCommand::with_name("state_transition")
            .about("Send state transition to anonify system.")
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
                .required(true)
                .default_value(DEFAULT_CONTRACT_ADDRESS)
            )
        )
        .subcommand(SubCommand::with_name("handshake")
            .about("handshake with other group members")
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_CONTRACT_ADDRESS)
            )
        )
        .subcommand(SubCommand::with_name("get_state")
            .about("Get state from anonify services.")
            .arg(Arg::with_name("keyfile-index")
                .short("i")
                .takes_value(true)
                .required(false)
                .default_value(DEFAULT_KEYFILE_INDEX)
            )
            .arg(Arg::with_name("contract-addr")
                .short("c")
                .takes_value(true)
                .required(true)
                .default_value(DEFAULT_CONTRACT_ADDRESS)
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
                .required(true)
                .default_value(DEFAULT_CONTRACT_ADDRESS)
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
