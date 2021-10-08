//! sibsecsh is a two factor authentication application designed to be used
//! as the login shell. It acts as a wrapper around the actual shell process.
//
//  Copyright (C) 2021 Zhang Maiyun <myzhang1029@hotmail.com>
//
//  This file is part of sib secure shell.
//
//  Sib secure shell is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  Sib secure shell is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with sib secure shell.  If not, see <https://www.gnu.org/licenses/>.
//

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
mod auth_email;
mod auth_totp;
mod config;
#[macro_use]
mod error;
mod extend_lettre;
mod ip;
mod parse_args;

use crate::auth::Authenticator;
use simplelog::{
    CombinedLogger, ConfigBuilder, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};
use std::ffi::OsString;
use users::get_current_username;

fn do_check_auth<'a>(
    authenticator: &impl auth::Authenticator<'a>,
    configuration: &config::Config,
) -> Result<(), String> {
    // First see whether -c is supplied
    let options = parse_args::parse_args();
    let mut other_options = options.1;
    let mut exec_options: Vec<String> = Vec::new();
    let is_accepted = match options.0 {
        Some(mut cmd) => {
            let tmp = authenticator.is_accepted_exec(&mut cmd);
            exec_options.push(String::from("-c"));
            exec_options.push(cmd);
            tmp
        }
        None => authenticator.is_accepted_login(),
    };
    exec_options.append(&mut other_options);
    match is_accepted {
        Some(value) => {
            if value {
                configuration.execute_shell(exec_options)
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
    const UNKNOWN: &str = "unknown user";
    let mut configuration = config::Config::default();
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
        TermLogger::new(LevelFilter::Error, log_format.clone(), TerminalMode::Mixed),
        WriteLogger::new(LevelFilter::Info, log_format, log_file),
    ]) {
        panic_gracefully!("Cannot create logger: {:?}", e);
    }

    if load_result.is_err() {
        warn!("No configuration supplied!");
    }
    let username = get_current_username()
        .or_else(|| Some(OsString::from(UNKNOWN)))
        .unwrap();
    let username = username.to_str().or(Some(UNKNOWN)).unwrap();
    info!("Login attempt from {} for {}", ip::get_from(), username);
    do_check_auth(
        &auth::BypassAuthenticator::init(&configuration),
        &configuration,
    )
    .or_else(print_err_exit)
    .ok();
    do_check_auth(
        &auth::LocalIPAuthenticator::init(&configuration),
        &configuration,
    )
    .or_else(print_err_exit)
    .ok();
    do_check_auth(
        &auth_email::EmailAuthenticator::init(&configuration),
        &configuration,
    )
    .or_else(print_err_exit)
    .ok();
    do_check_auth(
        &auth_totp::TotpAuthenticator::init(&configuration),
        &configuration,
    )
    .or_else(print_err_exit)
    .ok();
    panic_gracefully!("Sorry: All authenticators skipped");
}
