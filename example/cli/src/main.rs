#[macro_use]
extern crate clap;

use std::path::PathBuf;
use clap::{Arg, App, SubCommand, AppSettings, ArgMatches};
use dotenv::dotenv;
use rand::{rngs::OsRng, Rng};
use term::Term;
use crate::config::*;

mod term;
mod config;
mod commands;
mod error;

fn main() {
    dotenv().ok();
    env_logger::init();
    let default_root_dir = get_default_root_dir();

    let matches = App::new("anonify")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version(crate_version!())
        .author(crate_authors!())
        .about("Anonify's command line interface")
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

fn subcommand_anonify<R: Rng>(
    mut term: Term,
    root_dir: PathBuf,
    matches: &ArgMatches,
    rng: &mut R
) {
    let anonify_url = std::env::var("ANONIFY_URL").expect("ANONIFY_URL is not set.");

    match matches.subcommand() {
        ("deploy", Some(matches)) => {
            let keyfile_index: usize = matches.value_of("keyfile-index")
                .expect("Not found keyfile-index.")
                .parse()
                .expect("Failed to parse keyfile-index");
            let total_supply: u64 = matches.value_of("total_supply")
                .expect("Not found total_supply.")
                .parse()
                .expect("Failed to parse total_supply");

            commands::deploy(&mut term, root_dir, anonify_url, keyfile_index, total_supply, rng)
                .expect("Faild to deploy command");
        },
        ("get-state", Some(matches)) => {
            commands::get_state(&mut term, root_dir, anonify_url);
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
            .arg(Arg::with_name("total_supply")
                .short("t")
                .takes_value(true)
                .required(true)
            )
        )
        .subcommand(SubCommand::with_name("get-state"))
            .about("Get state from anonify services.")
}


// .arg(Arg::with_name("target address")
//                 .short("to")
//                 .long("target-address")
//                 .help("Specify a target address.")
//                 .takes_value(true)
//                 .required(true)
//             )


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
