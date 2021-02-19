extern crate home;
extern crate ipaddress;
extern crate lettre;
extern crate lettre_email;
#[macro_use]
extern crate log;
extern crate rand;
extern crate regex;
extern crate serde;
extern crate simplelog;
extern crate subprocess;
extern crate toml;
extern crate users;

mod auth;
mod config;
#[macro_use]
mod error;
mod extend_lettre;
mod ip;

use crate::auth::Authenticator;
use simplelog::{
    CombinedLogger, ConfigBuilder, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};
use std::ffi::OsString;
use users::get_current_username;

fn do_check_auth<'a>(
    authenticator: &impl auth::Authenticator<'a>,
    configuration: &config::Config,
    cmdline: Option<String>,
) -> Result<(), String> {
    match authenticator.is_accepted(cmdline) {
        Some(value) => {
            if value {
                configuration.execute_shell()
            } else {
                Err("Rejected".to_string())
            }
        }
        None => Ok(()),
    }
}

fn print_err_exit(msg: String) -> Result<(), String> {
    panic_gracefully!("Sorry: {}", msg);
}

fn main() {
    let mut configuration: config::Config = Default::default();
    let load_result = configuration.load_all_possible();
    let log_file = match configuration.open_log() {
        Ok(f) => f,
        Err(e) => panic_gracefully!("Cannot open log file: {:?}", e),
    };
    let log_format = ConfigBuilder::new()
        .set_time_to_local(true)
        .set_time_format_str("[%Y-%m-%d %H:%M:%S]")
        .set_target_level(LevelFilter::Error)
        .build();

    if let Err(e) = CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Warn, log_format.clone(), TerminalMode::Mixed),
        WriteLogger::new(LevelFilter::Info, log_format, log_file),
    ]) {
        panic_gracefully!("Cannot create logger: {:?}", e);
    }

    match load_result {
        Ok(_) => (),
        Err(_) => warn!("No configuration supplied!"),
    }
    const UNKNOWN: &'static str = "unknown user";
    let username = get_current_username()
        .or(Some(OsString::from(UNKNOWN)))
        .unwrap();
    let username = username.to_str().or(Some(UNKNOWN)).unwrap();
    info!("Login attempt from {} for {}", ip::get_from_ip(), username);
    do_check_auth(
        &auth::BypassAuthenticator::init(&configuration),
        &configuration,
        None,
    )
    .or_else(print_err_exit)
    .ok();
    do_check_auth(
        &auth::LocalIPAuthenticator::init(&configuration),
        &configuration,
        None,
    )
    .or_else(print_err_exit)
    .ok();
    do_check_auth(
        &auth::EmailAuthenticator::init(&configuration),
        &configuration,
        None,
    )
    .or_else(print_err_exit)
    .ok();
    panic_gracefully!("Sorry: Auth failed");
}
