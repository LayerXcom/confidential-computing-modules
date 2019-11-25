#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;

use clap::{Arg, App, SubCommand, AppSettings, ArgMatches};

mod term;
mod config;

fn main() {
    let matches = App::new("zface")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version(crate_version!())
        .author(crate_authors!())
        .about("Anonify's command line interface")
        .subcommand(anonify_commands_definition())
        .get_matches();


    println!("Hello, world!");
}

//
// Anonify Sub Commands
//

const ANONIFY_COMMAND: &'static str = "anonify";

fn subcommand_anonify(){

}

fn anonify_commands_definition<'a, 'b>() -> App<'a, 'b> {
    unimplemented!();
}
