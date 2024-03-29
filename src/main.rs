//! sibsecsh is a two factor authentication application designed to be used
//! as the login shell. It acts as a wrapper around the actual shell process.
//
//  Copyright (C) 2021 Zhang Maiyun <me@maiyun.me>
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

#![forbid(unsafe_code)]
#![warn(
    clippy::pedantic,
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    variant_size_differences
)]

mod auth;
mod auth_email;
mod auth_totp;
mod auth_yubico;
mod config;
mod ip;
mod parse_args;

use crate::auth::Authenticator;
use log::{info, warn};
use simplelog::{
    ColorChoice, CombinedLogger, ConfigBuilder, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};

fn do_check_auth<'a>(
    authenticator: &impl Authenticator<'a>,
    configuration: &config::SecRcCfg,
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
                configuration
                    .execute_shell(exec_options)
                    .map_err(|e| format!("{e}"))
            } else {
                Err("Rejected".to_string())
            }
        }
        None => Ok(()),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn print_err_exit(msg: String) -> Result<(), String> {
    panic!("Sorry: {msg}");
}

fn main() {
    // Wait for user input before panic!king.
    std::panic::set_hook(Box::new(|panic_info| {
        if let Some(location) = panic_info.location() {
            eprint!("Panic occurred at {}:{}", location.file(), location.line());
        } else {
            eprint!("Panic occurred");
        }
        if let Some(msg) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!(": {msg}");
        } else if let Some(msg) = panic_info.payload().downcast_ref::<String>() {
            eprintln!(": {msg}");
        } else {
            eprintln!();
        }
        std::io::stdin().read_line(&mut String::new()).unwrap();
    }));

    let mut configuration = config::SecRcCfg::default();
    let load_result = configuration.load_all_possible();
    let log_file = match configuration.open_log() {
        Ok(f) => f,
        Err(e) => panic!("Cannot open log file: {e}"),
    };
    let log_format = ConfigBuilder::new()
        .set_time_offset_to_local()
        // Just use UTC if simplelog can't determine the offset
        .or_else::<&mut ConfigBuilder, _>(Ok)
        .unwrap()
        .set_time_format_rfc3339()
        .set_target_level(LevelFilter::Error)
        .build();

    if let Err(e) = CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Warn,
            log_format.clone(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(LevelFilter::Info, log_format, log_file),
    ]) {
        panic!("Cannot create logger: {e}");
    }

    if load_result.is_err() {
        warn!("No configuration supplied!");
    }
    let username = whoami::username();
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
    do_check_auth(
        &auth_yubico::YubicoAuthenticator::init(&configuration),
        &configuration,
    )
    .or_else(print_err_exit)
    .ok();
    panic!("Sorry: All authenticators skipped");
}
